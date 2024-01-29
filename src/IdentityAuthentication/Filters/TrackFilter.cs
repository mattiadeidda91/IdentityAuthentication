using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityAuthentication.Filters
{
    public class TrackFilter : IAsyncActionFilter
    {
        private readonly ILogger<TrackFilter> logger;

        public TrackFilter(ILogger<TrackFilter> logger)
        {
            this.logger = logger;
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var request = context.HttpContext.Request;

            var requestBody = context.ActionArguments.FirstOrDefault().Value as string;

            logger.LogInformation($"Request: {request.Method} {request.Path} {requestBody}");

            var responseContext = await next();

            var response = responseContext.HttpContext.Response;

            logger.LogInformation($"Response: {response.StatusCode}");
        }
    }
}
