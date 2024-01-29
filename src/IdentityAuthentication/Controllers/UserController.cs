using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Abstractions.Utility;
using IdentityAuthentication.Filters;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace IdentityAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize(Policy = "UserActive")] is global
    public class UserController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;

        public UserController(UserManager<ApplicationUser> userManager)
        {
            this.userManager = userManager;
        }

        [AuthRole(CustomRoles.Administrator, CustomRoles.User, CustomRoles.Reader)]
        [HttpGet]
        public async Task<IActionResult> GetUser([Required] string username)
        {
            var user = await userManager.FindByEmailAsync(username);

            return StatusCode(user != null ? StatusCodes.Status200OK : StatusCodes.Status404NotFound, user);
        }

        [AuthRole(CustomRoles.Administrator, CustomRoles.User, CustomRoles.Reader)]
        [HttpGet("is-locked")]
        public async Task<IActionResult> IsLocked([Required] string username)
        {
            var user = await userManager.FindByEmailAsync(username);

            if (user != null)
            {
                var isEnable = await userManager.IsLockedOutAsync(user);  //user.LockoutEnd.GetValueOrDefault() <= DateTimeOffset.UtcNow

                return Ok(isEnable);
            }
            else
                return NotFound();
        }

        [AuthRole(CustomRoles.Administrator, CustomRoles.User)]
        [HttpGet("roles")]
        public async Task<IActionResult> GetUserRoles([Required] string username)
        {
            var user = await userManager.FindByEmailAsync(username);
            if (user != null)
            {
                var claims = await userManager.GetRolesAsync(user);

                return Ok(claims);
            }
            else
                return NotFound();
        }

        [AuthRole(CustomRoles.Administrator)]
        [HttpPut]
        public async Task<IActionResult> UpdateUser([Required] ApplicationUser user)
        {
            var result = await userManager.UpdateAsync(user);

            return StatusCode(result.Succeeded ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest, user);
        }

        [AuthRole(CustomRoles.Administrator)]
        [HttpPut("set-lockout-enable")]
        public async Task<IActionResult> DisableUser([Required] string username, bool isEnable)
        {
            var user = await userManager.FindByEmailAsync(username);

            if (user != null)
            {
                var result = await userManager.SetLockoutEndDateAsync(user, isEnable ? null : DateTimeOffset.UtcNow.AddDays(7));

                return StatusCode(result.Succeeded ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest);
            }
            else
                return NotFound();
        }

        [AuthRole(CustomRoles.Administrator)]
        [HttpDelete]
        public async Task<IActionResult> DeleteUser([Required] string username)
        {
            var user = await userManager.FindByIdAsync(username);

            if (user != null)
            {
                var result = await userManager.DeleteAsync(user);

                return StatusCode(result.Succeeded ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest);
            }
            else
                return NotFound();
        }
    }
}
