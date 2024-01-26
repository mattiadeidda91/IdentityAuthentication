using IdentityAuthentication.Abstractions.Models.Dto;

namespace IdentityAuthentication.Dependencies.Services
{
    public interface IIdentityService
    {
        Task<LoginResponseDto> LoginAsync(LoginRequestDto registerRequestDto);
        Task<RegisterResponseDto> RegisterAsync(RegisterRequestDto registerRequestDto);
    }
}