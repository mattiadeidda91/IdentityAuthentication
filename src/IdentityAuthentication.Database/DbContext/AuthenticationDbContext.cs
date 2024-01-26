using IdentityAuthentication.Abstractions.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuthentication.Database.DbContext
{
    public class AuthenticationDbContext 
        : IdentityDbContext<ApplicationUser, ApplicationRole, Guid, IdentityUserClaim<Guid>, ApplicationUserRole, 
            IdentityUserLogin<Guid>, IdentityRoleClaim<Guid>, IdentityUserToken<Guid>>
    {
        public AuthenticationDbContext(DbContextOptions options) 
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(user =>
            {
                user.Property(u => u.FirstName).HasMaxLength(256).IsRequired();
                user.Property(u => u.LastName).HasMaxLength(256);
            });

            builder.Entity<ApplicationUserRole>(userRole =>
            {
                userRole.HasKey(ur => new {ur.UserId, ur.RoleId});
                userRole.HasOne(ur => ur.Role)
                    .WithMany(r => r.UserRoles).HasForeignKey(r => r.RoleId).IsRequired();
                userRole.HasOne(ur => ur.User)
                    .WithMany(r => r.UserRoles).HasForeignKey(r => r.UserId).IsRequired();
            });
        }
    }
}
