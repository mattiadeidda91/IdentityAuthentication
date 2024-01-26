using IdentityAuthentication.Abstractions.Models.Dto;
using IdentityAuthentication.Dependencies.Services;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAuthentication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IIdentityService identityService;

        public AuthController(ILogger<AuthController> logger, IIdentityService identityService)
        {
            this.identityService = identityService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequestDto loginRequest)
        {
           var loginResponse = await identityService.LoginAsync(loginRequest);

            if(loginResponse != null)
                return Ok(loginResponse);
            else
                return BadRequest();
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequestDto registerRequest)
        {
            var valid = ModelState.IsValid;

            var registerResponse = await identityService.RegisterAsync(registerRequest);

            return StatusCode(registerResponse.Success ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest, 
                registerResponse);
        }
    }
}