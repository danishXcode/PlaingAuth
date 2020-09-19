using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using plainAuth.Context;
using plainAuth.models;

namespace plainAuth.Controllers
{
    [Microsoft.AspNetCore.Mvc.Route("[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        private IConfiguration _configutation;
        private readonly UserManager<UserModel> _userManager;
        private readonly ApplicationDbContext _appDbContext;

        public UserController(IConfiguration configuration, 
            UserManager<UserModel> userManager,
            ApplicationDbContext application
            )
        {
            _configutation = configuration;
            _userManager = userManager;
            _appDbContext = application;
        }

        [HttpGet("login")]
        public async Task<IActionResult> loginAsync(string uname,string pwd)
        {
            UserModel userModel = new UserModel();
            userModel.FullName = uname;
            userModel.UserName = uname;
            userModel.expass = pwd;


            IActionResult result = Unauthorized();

            var user = await Authuser(userModel);
            if (user != null)
            {

                var tokenstr = GenrateJSonWEbToken(user);
                return result = Ok(new { token = tokenstr });
            }
            return result;
        }

        private string GenrateJSonWEbToken(UserModel user)
        {
            var secutiykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configutation["Jwt:Key"]));

            var credentials = new SigningCredentials(secutiykey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub,user.FullName),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role,"admin")
            };


            var tokenstr = new JwtSecurityToken(
                issuer: _configutation["Jwt:Issuer"],
                audience: _configutation["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials
                );
            return  new JwtSecurityTokenHandler().WriteToken(tokenstr);

        }

        private async Task<UserModel> Authuser(UserModel userModel)
        {
            if (!string.IsNullOrEmpty(userModel.UserName) && !string.IsNullOrEmpty(userModel.expass))
            {
                // get the user to verifty
                var userToVerify = await _userManager.FindByNameAsync(userModel.UserName);

                if (userToVerify != null)
                {
                    // check the credentials  
                    if (await _userManager.CheckPasswordAsync(userToVerify, userModel.expass))
                    {
                        return userModel;
                    }
                }
            }

            // Credentials are invalid, or account doesn't exist
            return null;
        }
        [Authorize(Roles ="admin")]
        [HttpPost("post")]
        public string post()
        {

            var idn = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claims = idn.Claims.ToList();
            return "sir : " + claims[0];
        }

        [Authorize]
        [HttpGet("getvalue")]
        [Authorize(Roles = "user")]
        public ActionResult<IEnumerable<string>> get()
        {
            return new string[] { "v1", "v2" };
        }


        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(UserModel model)
        {

            

             var result = await _userManager.CreateAsync(model, model.expass);

            if (!result.Succeeded) return new BadRequestObjectResult(Errors.AddErrorsToModelState(result, ModelState));

            await _appDbContext.SaveChangesAsync();

            return new OkResult();



        }


    }
}
