using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;

namespace IdentityAuthentication.Abstractions.Extensions
{
    public static class SwaggerBuilderExtension
    {
        public static IServiceCollection SwaggerBuild(this IServiceCollection services)
        {
            services.AddSwaggerGen(options =>
            {
                //options.SwaggerDoc("v1", new OpenApiInfo { Title = "IdentityAuthentication", Version = "v1" });
                //options.EnableAnnotations();
                options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
                {
                    Name = HeaderNames.Authorization,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = JwtBearerDefaults.AuthenticationScheme,
                    In = ParameterLocation.Header,
                    Description = string.Join(Environment.NewLine
                               , $"<p>Please enter '{JwtBearerDefaults.AuthenticationScheme}' [space] and your token in the text input below.</p>"
                               , $"<p>Example: '{JwtBearerDefaults.AuthenticationScheme} 12345abcdef' </p>")
                });

                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = JwtBearerDefaults.AuthenticationScheme
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });

            return services;
        }
    }
}
