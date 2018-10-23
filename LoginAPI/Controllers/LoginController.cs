using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using LoginAPI.Authentication;
using LoginAPI.Authentication.Helpers;
using LoginAPI.Authentication.Tables;
using LoginAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace LoginAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        private readonly IdentityContext _DB;
        private readonly IConfiguration _Config;
        private readonly IHostingEnvironment Env;

        public LoginController(IdentityContext DB, IConfiguration Config, IHostingEnvironment env)
        {
            _DB = DB;
            _Config = Config;
            Env = env;

        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody]LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.ValidationState);
            }

            IActionResult badLogin = Unauthorized();
            
            if (await _DB.VerifiyPasswordAsync(model.Email, model.Password))
            {
                var roles = _DB.Users.Where(x => x.Email == model.Email)
                    .SelectMany(x => x.Roles)
                    .Select(x => x.Role)
                    .Select(x => new Claim(ClaimTypes.Role, x.Description)).ToList();



                var TokenSecurity = GetToken(_DB.Users.Where(x => x.Email == model.Email).FirstOrDefault(), roles);


                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(TokenSecurity),
                    IssuedAt = TokenSecurity.ValidFrom,
                    ExpiresAt = TokenSecurity.ValidTo,
                    model.Email,
                    Message = "Have a nice day!"
            });
            }

            return badLogin;
        }

        private JwtSecurityToken GetToken(User user, List<Claim> claims)
        {
            var rsaHelper = new RsaKeyHelpers(this.Env, this._Config);
            // Persist the Keys
            var Keys = rsaHelper.TryGetOrGenerateKeys();

            var _KeysRsa = new RSACryptoServiceProvider();
            _KeysRsa.FromxmlString(Keys.PrivateKey);
            var key = new RsaSecurityKey(_KeysRsa.ExportParameters(true));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        

            var token = 
               new JwtSecurityToken(_Config["Jwt:Issuer"],
              _Config["Jwt:Issuer"],
              claims,
              notBefore: DateTime.Now,
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: creds);

            return token;
        }
    }
}