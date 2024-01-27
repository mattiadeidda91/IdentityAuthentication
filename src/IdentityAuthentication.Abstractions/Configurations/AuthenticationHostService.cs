using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Abstractions.Utility;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityAuthentication.Abstractions.Configurations
{
    public class AuthenticationHostService : IHostedService
    {
        private readonly IServiceProvider serviceProvider;

        public AuthenticationHostService(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = serviceProvider.CreateScope();

            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            var roleNames = new List<string>() { CustomRoles.Administrator,  CustomRoles.User,  CustomRoles.Reader };

            foreach (var role in roleNames)
            {
                // If Role doesn't exists, then create it
                var roleExist = await roleManager.RoleExistsAsync(role);

                if (!roleExist)
                {
                    await roleManager.CreateAsync(new ApplicationRole(role));
                }
            }

            var user = new ApplicationUser()
            {
                FirstName = "Admin",
                LastName = "Admin",
                Email = "admin@admin.com",
                UserName = "admin@admin.com"
            };

            var userExist = await userManager.FindByEmailAsync(user.Email);

            //If Admin user doesn't exists, then i create it
            if (userExist == null)
            {
                var userCreated = await userManager.CreateAsync(user, "Admin123!");

                //Link role to Admin user
                if (userCreated.Succeeded)
                {
                    _ = await userManager.AddToRolesAsync(user, new string[] { CustomRoles.Administrator, CustomRoles.User });
                }
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    }
}
