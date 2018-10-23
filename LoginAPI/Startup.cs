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

        public Startup(IConfiguration configuration, IHostingEnvironment env)
        {
            Configuration = configuration;
            Env = env;
        }

        public IConfiguration Configuration { get; }
        public IHostingEnvironment Env;

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

            var rsaHelper = new RsaKeyHelpers(Env, Configuration);
            // Persist the Keys
            var Keys = rsaHelper.TryGetOrGenerateKeys();

            var _KeysRsa = new RSACryptoServiceProvider();
            _KeysRsa.FromxmlString(Keys.PublicKey);
            
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
                    IssuerSigningKey = new RsaSecurityKey(_KeysRsa.ExportParameters(false))
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
