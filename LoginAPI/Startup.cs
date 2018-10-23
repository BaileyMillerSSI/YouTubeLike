using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LoginAPI.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using LoginAPI.Authentication.Helpers;
using LoginAPI.Authentication.Tables;
using System.IO;
using Microsoft.AspNetCore.Hosting.Server;
using System.Security.Cryptography;

namespace LoginAPI
{
    public class Startup
    {

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => 
                      builder.WithOrigins("*")
                      .AllowAnyMethod()
                      .AllowAnyHeader()
                      .AllowCredentials()
                .Build());
            });

            // Persist the Keys
            var Keys = TryGetOrGenerateKeys();

            var _KeysRsa = new RSACryptoServiceProvider();
            _KeysRsa.FromXmlString(Keys.PrivateKey);
            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false, // Change to True for production
                    ValidateAudience = false, // Change to True for production
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = Configuration["Jwt:Issuer"],
                    ValidAudience = Configuration["Jwt:Issuer"],
                    IssuerSigningKey = new RsaSecurityKey(_KeysRsa.ExportParameters(true))
                };
            });
            
            var connection = Configuration.GetConnectionString("Default");
            services.AddDbContextPool<IdentityContext>(options=> options.UseSqlServer(connection));

            using (var db = new IdentityContext(new DbContextOptionsBuilder<IdentityContext>().UseSqlServer(connection).Options))
            {
                var Status = false;
                TimeSpan timeout = TimeSpan.FromSeconds(60);
                var StartTime = DateTime.Now;
                do
                {
                    try
                    {
                        db.Database.Migrate();
                        Status = true;
                        var cleanDb = Environment.GetEnvironmentVariable("CleanDatabase");
                        if (cleanDb == "\"'True'\"")
                        {
                            db.Database.EnsureDeleted();
                            db.SaveChanges();
                            db.Database.Migrate();
                        }

                        // Seed if needed
                        // Check if debug@live.com exists
                        if (!db.Users.UserExists("debug@live.com"))
                        {
                            var hashData = HashHelpers.GenerateHash("ATesterBot");
                            // Create this user
                            var newUser = new User()
                            {
                                Email = "debug@live.com",
                                FirstName = "Debugging",
                                LastName = "Tester",
                                Credentials = new UserSecurity()
                                {
                                    SecurityHash = hashData.Hash,
                                    SecuritySalt = Convert.ToBase64String(hashData.Salt)
                                }
                            };

                            var testerRole = new Role() { Description = "Tester" };
                            db.Roles.Add(testerRole);

                            db.SaveChanges();

                            newUser.Roles.Add(new UserRole() { RoleId = testerRole.RoleId, UserId = newUser.UserId });


                            db.Users.Add(newUser);
                            db.SaveChanges();
                        }
                    }
                    catch (Exception e)
                    {

                    }
                } while (Status == false || (DateTime.Now - StartTime).TotalSeconds > timeout.TotalSeconds);
            }
        }

        private (String PrivateKey, String PublicKey) TryGetOrGenerateKeys()
        {
            var privateKey = "";
            var publicKey = "";

            var Keys = RsaKeyHelpers.GenerateKeys();
            
            using (var keyRef = File.Open(Configuration.GetSection("Keys:Public").Value, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
            {
                if (keyRef.Length == 0)
                {
                    var buf = Encoding.UTF8.GetBytes(Keys.PublicKey);
                    keyRef.Write(buf, 0, buf.Length);
                    keyRef.Flush();
                }
                using (var reader = new StreamReader(keyRef))
                {
                    publicKey = reader.ReadToEnd();
                }
            }

            using (var keyRef = File.Open(Configuration.GetSection("Keys:Private").Value, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
            {
                if (keyRef.Length == 0)
                {
                    var buf = Encoding.UTF8.GetBytes(Keys.PrivateKey);
                    keyRef.Write(buf, 0, buf.Length);
                    keyRef.Flush();
                }
                using (var reader = new StreamReader(keyRef))
                {
                    privateKey = reader.ReadToEnd();
                }
            }

            return (privateKey, publicKey);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseCors("CorsPolicy");
            app.UseAuthentication();
            app.UseMvc();


        }
    }
}
