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
using plainAuth.models.UMC;

namespace plainAuth.Controllers
{
    [Microsoft.AspNetCore.Mvc.Route("[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        private IConfiguration _configutation;
        private readonly UserManager<UserModel> _userManager;
        private readonly ApplicationDbContext _appDbContext;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(IConfiguration configuration, 
            UserManager<UserModel> userManager,
            ApplicationDbContext application,
            RoleManager<IdentityRole> roleManager
            )
        {
            _configutation = configuration;
            _userManager = userManager;
            _appDbContext = application;
            _roleManager = roleManager;
        }

        [HttpGet("login")]
        public async Task<IActionResult> loginAsync(string uname,string pwd)
        {
            UserModel userModel = new UserModel();
            userModel.UserName = uname;
            userModel.Password = pwd;
            IActionResult result = Unauthorized();

            var user = await Authuser(userModel);
            if (user != null)
            {

                var tokenstr = GenrateJSonWEbToken(user);
                return result = Ok(new { token = tokenstr });
            }
            return result;
        }

        private async Task<string> GenrateJSonWEbToken(UserModel user)
        {
            var secutiykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configutation["Jwt:Key"]));

            var credentials = new SigningCredentials(secutiykey, SecurityAlgorithms.HmacSha256);


            var claims =new List<Claim>()
            {
            new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),

            };

             var user1 = await _userManager.FindByNameAsync(user.UserName);
            // Get the roles for the user
            var roles = await  _userManager.GetRolesAsync(user1);
            foreach (var item in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, item));
            }



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
            if (!string.IsNullOrEmpty(userModel.UserName) && !string.IsNullOrEmpty(userModel.Password))
            {
                // get the user to verifty
                var userToVerify = await _userManager.FindByNameAsync(userModel.UserName);

                if (userToVerify != null)
                {
                    // check the credentials  
                    if (await _userManager.CheckPasswordAsync(userToVerify, userModel.Password))
                    {
                        return userModel;
                    }
                }
            }

            // Credentials are invalid, or account doesn't exist
            return null;
        }
        [Authorize(Roles = "Admin")]
        [HttpPost("post")]
        public string post()
        {

            var idn = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claims = idn.Claims.ToList();
            return "sir : " + claims[0];
        }

        [Authorize]
        [HttpGet("getvalue")]
        [Authorize(Roles = "User")]
        public ActionResult<IEnumerable<string>> get()
        {
            return new string[] { "v1", "v2" };
        }


        [HttpPost("RegisterTenant")]
        public async Task<IActionResult> RegisterAsync(UserModel model)
        {
            bool adminRoleExists = await _roleManager.RoleExistsAsync("Admin");
            if (!adminRoleExists)
            {
               await _roleManager.CreateAsync(new IdentityRole("Admin"));
            }
            var result = await _userManager.CreateAsync(model, model.Password);
            

            model.tenant = new Tenant()
            {
                TenantName = model.FullName
            };

            if (!result.Succeeded) return new BadRequestObjectResult(Errors.AddErrorsToModelState(result, ModelState));
           
            await _appDbContext.SaveChangesAsync();
            var roleadded = await _userManager.AddToRoleAsync(model, "Admin");
            await _appDbContext.SaveChangesAsync();

            return new OkResult();
        }

        [HttpPost("RegisterUser")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RegisteUserAsync(UserModelRole model)
        {
            bool adminRoleExists = await _roleManager.RoleExistsAsync(model.Role);
            if (!adminRoleExists)
            {
                await _roleManager.CreateAsync(new IdentityRole(model.Role));
            }

            var idn = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claims = idn.Claims.ToList();

            model.tenant = new Tenant()
            {
                TenantName = model.FullName
            };

            var result = await _userManager.CreateAsync(model, model.Password);
            await _userManager.AddToRoleAsync(model, model.Role);

            if (!result.Succeeded) return new BadRequestObjectResult(Errors.AddErrorsToModelState(result, ModelState));

            await _appDbContext.SaveChangesAsync();

            return new OkResult();
        }

    }
}
