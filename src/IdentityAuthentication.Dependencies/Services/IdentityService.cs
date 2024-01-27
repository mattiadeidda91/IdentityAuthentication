using IdentityAuthentication.Abstractions.Configurations.Options;
using IdentityAuthentication.Abstractions.Models.Dto;
using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Abstractions.Utility;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityAuthentication.Dependencies.Services
{
    public class IdentityService : IIdentityService
    {
        public readonly JwtOptions jwtOptions;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;

        public IdentityService(IOptions<JwtOptions> jwtOptions, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            this.jwtOptions = jwtOptions.Value;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public async Task<LoginResponseDto?> LoginAsync(LoginRequestDto registerRequestDto)
        {
            var loginResponse = await signInManager.PasswordSignInAsync(registerRequestDto.Username, registerRequestDto.Password, false, false);
            
            if (!loginResponse.Succeeded)
            {
                return null;
            }

            var user = await userManager.FindByNameAsync(registerRequestDto.Username);
            var userRoles = await userManager.GetRolesAsync(user);

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.GivenName, user.FirstName!),
                new Claim(ClaimTypes.Surname, user.LastName ?? string.Empty),
            }
            .Union(userRoles.Select(role => new Claim(ClaimTypes.Role, role))).ToList();

            return GenerateToken(claims);
        }

        public async Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto registerRequestDto)
        {
            var user = new ApplicationUser
            {
                FirstName = registerRequestDto.FirstName,
                LastName = registerRequestDto.LastName,
                Email = registerRequestDto.Email,
                UserName = registerRequestDto.Email
            };

            var createdResult = await userManager.CreateAsync(user, registerRequestDto.Password);

            if(createdResult.Succeeded)
            {
                _ = await userManager.AddToRoleAsync(user, CustomRoles.User); //Default Registration Role
            }

            return new RegisterResponseDto
            {
                Success = createdResult.Succeeded,
                Errors = createdResult.Errors.Select(e => e.Description)
            };
        }

        private LoginResponseDto GenerateToken(IList<Claim> claims)
        {
            var symmetricSignature = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Signature!));
            var signingCredentials = new SigningCredentials(symmetricSignature, SecurityAlgorithms.HmacSha256Signature);

            var securityToken = new JwtSecurityToken(
                jwtOptions.Issuer, 
                jwtOptions.Audience, 
                claims, 
                DateTime.UtcNow, 
                DateTime.UtcNow.AddDays(10), 
                signingCredentials);

            var token = new JwtSecurityTokenHandler().WriteToken(securityToken);

            return new LoginResponseDto { Token = token };
        }
    }
}
