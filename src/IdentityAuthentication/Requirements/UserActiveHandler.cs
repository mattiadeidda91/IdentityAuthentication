using IdentityAuthentication.Abstractions.Models.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityAuthentication.Requirements
{
    public class UserActiveHandler : AuthorizationHandler<UserActiveRequirement>
    {
        private readonly UserManager<ApplicationUser> userManager;

        public UserActiveHandler(UserManager<ApplicationUser> userManager) 
        {
            this.userManager = userManager;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, UserActiveRequirement requirement)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(context.User);
            ArgumentNullException.ThrowIfNull(context.User.Identity);

            if (context.User.Identity.IsAuthenticated)
            {
                var id = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var user = await userManager.FindByIdAsync(id);

                if(user != null)
                {
                    var isLocked = await userManager.IsLockedOutAsync(user);

                    if(!isLocked) 
                        context.Succeed(requirement);
                }
            }
        }
    }
}
