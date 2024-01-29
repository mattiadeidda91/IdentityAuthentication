using IdentityAuthentication.Abstractions.Configurations;
using IdentityAuthentication.Abstractions.Configurations.Options;
using IdentityAuthentication.Abstractions.Extensions;
using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Database.DbContext;
using IdentityAuthentication.Dependencies.Services;
using IdentityAuthentication.Filters;
using IdentityAuthentication.Requirements;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//Services
builder.Services.AddScoped<IIdentityService, IdentityService>();
builder.Services.AddScoped<IAuthorizationHandler, UserActiveHandler>();

//Hosted Service
builder.Services.AddHostedService<AuthenticationHostService>();

//Options
var jwtSection = builder.Configuration.GetSection(nameof(JwtOptions));
builder.Services.Configure<JwtOptions>(jwtSection);
var jwtOptions = jwtSection.Get<JwtOptions>();

//Add DbContext
builder.Services.AddDbContext<AuthenticationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SqlConnection"));
});

//Add .Net Core Identity
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.User.RequireUniqueEmail= true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;

})
.AddEntityFrameworkStores<AuthenticationDbContext>()
.AddDefaultTokenProviders(); //objects to generate token for reset/change password

builder.Services.AddControllers();

//Jwt Auth
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = builder.Environment.IsProduction();
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtOptions.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtOptions.Audience,
        ValidateLifetime = true, //Validate token expiration
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Signature!)),
        RequireExpirationTime = true,
        ClockSkew = TimeSpan.FromMinutes(5) //The Default is 5 minutes, Token is valid for 5 mins after expiration
    };
});

builder.Services.AddAuthorization(options =>
{
    //All controllers require authorized user and custom Requirement (Not locked User) -> NOT WORKING
    var policyBuilder = new AuthorizationPolicyBuilder().RequireAuthenticatedUser();
    policyBuilder.Requirements.Add(new UserActiveRequirement());
    options.FallbackPolicy = options.DefaultPolicy = policyBuilder.Build();

    options.AddPolicy("UserActive", policy =>
    {
        policy.Requirements.Add(new UserActiveRequirement());
    });
});

//Swagger
builder.Services.SwaggerBuild();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//Add global Filters
builder.Services.AddControllersWithViews(options =>
{
    //Set global authorize policy
    options.Filters.Add(new AuthorizeFilter("UserActive"));
    //Set global filter
    options.Filters.Add<TrackFilter>();
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//app.UseCors(options =>
//{
//    options.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader().Build();
//});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
