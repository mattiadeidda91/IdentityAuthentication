using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Abstractions.Utility;
using IdentityAuthentication.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace IdentityAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;

        public UserController(UserManager<ApplicationUser> userManager)
        {
            this.userManager = userManager;
        }

        [AuthRole(CustomRoles.Administrator, CustomRoles.User)]
        [HttpGet]
        public async Task<IActionResult> GetUser([Required] string username)
        {
            var user = await userManager.FindByEmailAsync(username);

            return StatusCode(user != null ? StatusCodes.Status200OK : StatusCodes.Status404NotFound, user);
        }
    }
}
