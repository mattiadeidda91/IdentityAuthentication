using IdentityAuthentication.Abstractions.Configurations;
using IdentityAuthentication.Abstractions.Models.Entities;
using IdentityAuthentication.Database.DbContext;
using IdentityAuthentication.Dependencies.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddScoped<IIdentityService, IdentityService>();
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(nameof(JwtOptions)));

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

app.UseAuthorization();

app.MapControllers();

app.Run();
