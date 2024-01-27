using IdentityAuthentication.Abstractions.Configurations;
using IdentityAuthentication.Abstractions.Configurations.Options;
using IdentityAuthentication.Abstractions.Extensions;
using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Database.DbContext;
using IdentityAuthentication.Dependencies.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//Services
builder.Services.AddScoped<IIdentityService, IdentityService>();

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

//Hosted Service
builder.Services.AddHostedService<AuthenticationHostService>();

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
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Signature!)),
        RequireExpirationTime = true,
        ClockSkew = TimeSpan.FromMinutes(5) //The Default is 5 minutes
    };
});

builder.Services.AddAuthorization(options =>
{
    //All controllers require authorized user
    options.FallbackPolicy = options.DefaultPolicy; 
});

//Swagger
builder.Services.SwaggerBuild();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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
