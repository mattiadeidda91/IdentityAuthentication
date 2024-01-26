using Microsoft.AspNetCore.Identity;

namespace IdentityAuthentication.Abstractions.Models.Entities
{
    public class ApplicationRole : IdentityRole<Guid>
    {
        public virtual ICollection<ApplicationUserRole>? UserRoles { get; set; }

        public ApplicationRole() { }

        public ApplicationRole(string role)
            : base(role)
        {

        }
    }
}
