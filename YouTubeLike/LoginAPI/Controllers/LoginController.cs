using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LoginAPI.Authentication;
using LoginAPI.Authentication.Helpers;
using LoginAPI.Authentication.Tables;
using LoginAPI.Models;
using Microsoft.AspNetCore.Authorization;
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

        public LoginController(IdentityContext DB, IConfiguration Config)
        {
            _DB = DB;
            _Config = Config;

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
                return Ok(BuildToken(_DB.Users.Where(x=>x.Email == model.Email).FirstOrDefault()));
            }

            return Ok();
        }

        private string BuildToken(User user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_Config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
            };


            var allRoles = user.Roles.Select(x => new Claim(ClaimTypes.Role, x.Role.Description));

            claims.AddRange(allRoles.ToList());

            var token = 
               new JwtSecurityToken(_Config["Jwt:Issuer"],
              _Config["Jwt:Issuer"],
              claims,
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}