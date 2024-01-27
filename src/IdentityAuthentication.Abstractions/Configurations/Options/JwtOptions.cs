namespace IdentityAuthentication.Abstractions.Configurations.Options
{
    public class JwtOptions
    {
        public string? Signature { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public string? AccessTokenExpirationMinutes { get; set; }
        public string? RefreshTokenExpirationMinutes { get; set; }
    }
}
