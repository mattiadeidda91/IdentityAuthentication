using Microsoft.AspNetCore.Authorization;

namespace IdentityAuthentication.Filters
{
    public class AuthRoleAttribute: AuthorizeAttribute
    {
        public AuthRoleAttribute(params string[] roles)
        {
            Roles = string.Join(",", roles);
        }
    }
}
