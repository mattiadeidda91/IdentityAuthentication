using IdentityAuthentication.Abstractions.Configurations;
using IdentityAuthentication.Abstractions.Models.Dto;
using IdentityAuthentication.Abstractions.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

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

        public async Task<LoginResponseDto> LoginAsync(LoginRequestDto registerRequestDto)
        {
            var loginResponse = await signInManager.PasswordSignInAsync(registerRequestDto.Username, registerRequestDto.Password, false, false);
            
            if (!loginResponse.Succeeded)
            {
                return null;
            }

            //JWT TOKEN GENERATION
            return new LoginResponseDto() { Token = Guid.NewGuid().ToString() };

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

            return new RegisterResponseDto
            {
                Success = createdResult.Succeeded,
                Errors = createdResult.Errors.Select(e => e.Description)
            };
        }
    }
}
