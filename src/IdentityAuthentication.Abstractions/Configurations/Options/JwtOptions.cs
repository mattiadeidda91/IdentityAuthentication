namespace IdentityAuthentication.Abstractions.Configurations.Options
{
    public class JwtOptions
    {
        public string? Signature { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public int AccessTokenExpirationMinutes { get; set; }
        public int RefreshTokenExpirationMinutes { get; set; }
    }
}
