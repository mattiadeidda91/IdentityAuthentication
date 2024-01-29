using IdentityAuthentication.Abstractions.Configurations.Options;
using IdentityAuthentication.Abstractions.Models.Dto;
using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Abstractions.Utility;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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

        public async Task<LoginResponseDto?> LoginAsync(LoginRequestDto loginRequestDto)
        {
            var loginResponse = await signInManager.PasswordSignInAsync(loginRequestDto.Username, loginRequestDto.Password, false, false);
            
            if (!loginResponse.Succeeded)
            {
                return null;
            }

            var user = await userManager.FindByNameAsync(loginRequestDto.Username);
            var userRoles = await userManager.GetRolesAsync(user);

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.GivenName, user.FirstName!),
                new Claim(ClaimTypes.Surname, user.LastName ?? string.Empty),
            }
            .Union(userRoles.Select(role => new Claim(ClaimTypes.Role, role)))
            .ToList();

            var loginResult = GenerateToken(claims);

            //Save Refresh token properties to DB
            user.RefreshToken= loginResult.RefreshToken;
            user.RefreshTokenExpirationDate = DateTime.UtcNow.AddMinutes(jwtOptions.RefreshTokenExpirationMinutes);

            _ = await userManager.UpdateAsync(user);

            return loginResult;
        }

        public async Task<LoginResponseDto> RefreshTokenAsync(RefreshTokenRequestDto refreshTokenRequestDto)
        {
            var tokenValidation = await ValidateAccessToken(refreshTokenRequestDto.Token!);

            if (tokenValidation != null && tokenValidation.IsValid)
            {
                var userId = tokenValidation.ClaimsIdentity.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if(!string.IsNullOrEmpty(userId))
                {
                    var user = await userManager.FindByIdAsync(userId);

                    //Check token values to DB
                    if(user?.RefreshToken == null || 
                        user?.RefreshTokenExpirationDate < DateTime.UtcNow || 
                        user?.RefreshToken != refreshTokenRequestDto.RefreshToken)
                    {
                        return null;
                    }

                    var loginResponse = GenerateToken(tokenValidation.ClaimsIdentity.Claims);

                    user!.RefreshToken = loginResponse.RefreshToken;
                    user.RefreshTokenExpirationDate = DateTime.UtcNow.AddMinutes(jwtOptions.RefreshTokenExpirationMinutes);

                    _ = await userManager.UpdateAsync(user);

                    return loginResponse;
                }
            }

            return null;
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

            if (createdResult.Succeeded)
            {
                _ = await userManager.AddToRoleAsync(user, CustomRoles.User); //Default Registration Role
                //_ = await userManager.AddClaimsAsync(user, claims); //Default Registration Claims
            }

            return new RegisterResponseDto
            {
                Success = createdResult.Succeeded,
                Errors = createdResult.Errors.Select(e => e.Description)
            };
        }

        private async Task<TokenValidationResult> ValidateAccessToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = jwtOptions.Audience,
                ValidateLifetime = false, // set false to allow access to the user without checking the token expiration
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Signature!)),
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var tokenValidation = await new JwtSecurityTokenHandler().ValidateTokenAsync(token, tokenValidationParameters);

            ////Check if token is our jwt token with our roles and Alg
            //if(tokenValidation.SecurityToken is JwtSecurityToken jwtSecurityToken && jwtSecurityToken.Header.Alg == SecurityAlgorithms.HmacSha256Signature)
            //{
            //    return tokenValidation?.IsValid ?? false;
            //}

            return tokenValidation;
        }

        private LoginResponseDto GenerateToken(IEnumerable<Claim> claims)
        {
            var symmetricSignature = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Signature!));
            var signingCredentials = new SigningCredentials(symmetricSignature, SecurityAlgorithms.HmacSha256Signature);

            var securityToken = new JwtSecurityToken(
                jwtOptions.Issuer, 
                jwtOptions.Audience, 
                claims, 
                DateTime.UtcNow, 
                DateTime.UtcNow.AddMinutes(jwtOptions.AccessTokenExpirationMinutes),
                signingCredentials);

            var token = new JwtSecurityTokenHandler().WriteToken(securityToken);

            return new LoginResponseDto 
            { 
                Token = token, 
                RefreshToken = GenerateRefreshToken() 
            };
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[256];
            using var generator = RandomNumberGenerator.Create();
            generator.GetBytes(randomNumber);

            return Convert.ToBase64String(randomNumber);
        }
    }
}
