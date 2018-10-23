using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LoginAPI.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace LoginAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        private readonly IdentityContext _DB;

        public LoginController(IdentityContext DB)
        {
            _DB = DB;
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login()
        {


            return Ok();
        }
    }
}