namespace IdentityAuthentication.Abstractions.Models.Dto
{
    public class RefreshTokenRequestDto
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
    }
}
