using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// JWT 設定，展示用途，故使用簡單固定 key
var jwtKey = "this-is-a-demo-secret-key-1234567890";
var issuer = "demoTestHost";
var audience = "demoTestHostClient";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();

    return forecast;
})
.WithName("GetWeatherForecast");

/// <summary>
/// 登入路由：驗證 userid / password，成功後回傳 access token，並寫入 refresh token 到 cookie。
/// </summary>
app.MapPost("/login", (LoginRequest request, HttpResponse response) =>
{
    if (request.UserId != "user1" || request.Password != "12345")
    {
        return Results.Unauthorized();
    }

    var accessToken = GenerateToken(
        request.UserId,
        "access",
        DateTime.UtcNow.AddMinutes(20),
        issuer,
        audience,
        signingKey);

    var refreshToken = GenerateToken(
        request.UserId,
        "refresh",
        DateTime.UtcNow.AddHours(1),
        issuer,
        audience,
        signingKey);

    response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
    {
        HttpOnly = true,
        Secure = false, // 展示用途；正式環境請改 true
        SameSite = SameSiteMode.Strict,
        Expires = DateTimeOffset.UtcNow.AddHours(1)
    });

    return Results.Ok(new
    {
        message = "login success",
        token = accessToken
    });
});

/// <summary>
/// 刷新 token 路由：需同時驗證 bearer token 與 cookie 中的 refresh token，成功後回傳新的 access token。
/// </summary>
app.MapPost("/refresh-token", (HttpRequest request) =>
{
    var authHeader = request.Headers.Authorization.ToString();
    if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
    {
        return Results.Unauthorized();
    }

    var accessToken = authHeader["Bearer ".Length..].Trim();

    if (!ValidateToken(accessToken, issuer, audience, signingKey, expectedTokenType: "access", out var accessPrincipal))
    {
        return Results.Unauthorized();
    }

    if (!request.Cookies.TryGetValue("refreshToken", out var refreshToken) || string.IsNullOrWhiteSpace(refreshToken))
    {
        return Results.Unauthorized();
    }

    if (!ValidateToken(refreshToken, issuer, audience, signingKey, expectedTokenType: "refresh", out var refreshPrincipal))
    {
        return Results.Unauthorized();
    }

    var accessUserId = accessPrincipal?.FindFirst(ClaimTypes.Name)?.Value;
    var refreshUserId = refreshPrincipal?.FindFirst(ClaimTypes.Name)?.Value;

    if (string.IsNullOrWhiteSpace(accessUserId) ||
        string.IsNullOrWhiteSpace(refreshUserId) ||
        accessUserId != refreshUserId)
    {
        return Results.Unauthorized();
    }

    var newAccessToken = GenerateToken(
        accessUserId,
        "access",
        DateTime.UtcNow.AddMinutes(20),
        issuer,
        audience,
        signingKey);

    return Results.Ok(new
    {
        message = "refresh success",
        token = newAccessToken
    });
});

/// <summary>
/// 登出路由：驗證 bearer token 後刪除 cookie 中的 refresh token，完成登出。
/// </summary>
app.MapPost("/logout", (HttpRequest request, HttpResponse response) =>
{
    var authHeader = request.Headers.Authorization.ToString();
    if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer "))
    {
        return Results.Unauthorized();
    }

    var accessToken = authHeader["Bearer ".Length..].Trim();

    if (!ValidateToken(accessToken, issuer, audience, signingKey, expectedTokenType: "access", out _))
    {
        return Results.Unauthorized();
    }

    response.Cookies.Delete("refreshToken");

    return Results.Ok(new
    {
        message = "logout success"
    });
});

app.Run();

static string GenerateToken(
    string userId,
    string tokenType,
    DateTime expires,
    string issuer,
    string audience,
    SymmetricSecurityKey signingKey)
{
    var claims = new[]
    {
        new Claim(ClaimTypes.Name, userId),
        new Claim("tokenType", tokenType)
    };

    var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        expires: expires,
        signingCredentials: credentials);

    return new JwtSecurityTokenHandler().WriteToken(token);
}

static bool ValidateToken(
    string token,
    string issuer,
    string audience,
    SymmetricSecurityKey signingKey,
    string expectedTokenType,
    out ClaimsPrincipal? principal)
{
    principal = null;

    var tokenHandler = new JwtSecurityTokenHandler();

    try
    {
        principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        }, out _);

        var tokenType = principal.FindFirst("tokenType")?.Value;
        return tokenType == expectedTokenType;
    }
    catch
    {
        return false;
    }
}

record LoginRequest(string UserId, string Password);

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}