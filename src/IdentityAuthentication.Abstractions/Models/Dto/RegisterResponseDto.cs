namespace IdentityAuthentication.Abstractions.Models.Dto
{
    public class RegisterResponseDto
    {
        public bool Success { get; set; }
        public IEnumerable<string>? Errors { get; set; }
    }
}
