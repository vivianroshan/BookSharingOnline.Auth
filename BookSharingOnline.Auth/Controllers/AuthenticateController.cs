using BookSharingOnline.Auth.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace BookSharingOnline.Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticateController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim("Role", userRole));
                }
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    name= user.UserName,
                    role=userRoles[0]
                });
            }
            return Unauthorized();
        }

     

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterBoth([FromBody] RegisterModel model)
        {
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
            var emailDuplicate = await userManager.FindByEmailAsync(model.Email.ToLower());
            if (emailDuplicate != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Email Id Aldredy Exists!" });

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
           
            
            if (model.Role.ToLower() == "both") {
                if (!await roleManager.RoleExistsAsync(UserRoles.both))
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.both));
                await userManager.AddToRoleAsync(user, UserRoles.both);
            }
            else if (model.Role.ToLower() == "seller")
            {
                if (!await roleManager.RoleExistsAsync(UserRoles.seller))
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.seller));
                await userManager.AddToRoleAsync(user, UserRoles.seller);
            }
            else if (model.Role.ToLower() == "buyer")
            {
                if (!await roleManager.RoleExistsAsync(UserRoles.buyer))
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.buyer));
                await userManager.AddToRoleAsync(user, UserRoles.buyer);
            }

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }
    }
}
