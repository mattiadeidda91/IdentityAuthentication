using IdentityAuthentication.Abstractions.Models.Dto;

namespace IdentityAuthentication.Dependencies.Services
{
    public interface IIdentityService
    {
        Task<LoginResponseDto?> LoginAsync(LoginRequestDto loginRequestDto);
        Task<LoginResponseDto> RefreshTokenAsync(RefreshTokenRequestDto refreshTokenRequestDto);
        Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto registerRequestDto);
    }
}