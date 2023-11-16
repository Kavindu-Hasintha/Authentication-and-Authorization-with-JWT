global using Authentication_and_Authorization_with_JWT.Models;
global using System.ComponentModel.DataAnnotations;
global using Microsoft.AspNetCore.Mvc;
global using System.Security.Cryptography;
global using Microsoft.IdentityModel.Tokens;
global using System.Security.Claims;
global using System.IdentityModel.Tokens.Jwt;
global using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => // This line adds Swagger services to the application
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Description = "Standard Authorization header using the Bearer scheme (\"bearer {token}\")",
        // Describes how the authorization should be done, in this case, using a Bearer token in the Authorization header.
        In = ParameterLocation.Header, //  Specifies where the token should be placed, in this case, in the header.
        Name = "Authorization", // The name of the header where the token is expected, which is "Authorization".
        Type = SecuritySchemeType.ApiKey // Specifies the type of security scheme, which is an API key in this case.
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});
// setting up Swagger documentation for an ASP.NET Core API and specifying that the API uses OAuth 2.0 for authentication.
// It also adds a filter to ensure that each API operation is documented with the security requirements, indicating the need
// for a Bearer token in the Authorization header.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(
        options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidateIssuerSigningKey = true,
                // ValidIssuer = builder.Configuration["JWT:Issuer"],
                // ValidAudience = builder.Configuration["JWT:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                    builder.Configuration["Token:Key"])),
            };
        });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication(); // Should be above useAuthorization

app.UseAuthorization();

app.MapControllers();

app.Run();
