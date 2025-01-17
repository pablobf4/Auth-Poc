using AuthService.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly string _jwtKey = "SuperSecretKey123SuperSecretKey123"; 

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (request.Username == "user" && request.Password == "user") 
        {
            var accessToken = GenerateToken(request.Username, 5); 
            var refreshToken = GenerateToken(request.Username, 1440); 

            Response.Cookies.Append("AccessToken", accessToken, new CookieOptions
            {
                HttpOnly = true,          // O cookie será acessível apenas pelo servidor
                Secure = false,           // HTTPS desativado para testes locais
                SameSite = SameSiteMode.Lax, // Permitir envio entre subdomínios
                Domain = ".mundial.mat",    // Permitir compartilhamento entre cliente01.local e cliente02.local
                Path = "/",               // Disponível para todas as rotas
                Expires = DateTime.UtcNow.AddMinutes(5) // Tempo de expiração
            });

            Response.Cookies.Append("RefreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Lax,
                Domain = ".mundial.mat",      // Permitir compartilhamento entre cliente01.local e cliente02.local
                Path = "/",               // Disponível para todas as rotas
                Expires = DateTime.UtcNow.AddDays(1) // Tempo de expiração
            });

            return Ok(new { Message = "Login successful" });
        }

        return Unauthorized("Invalid credentials");
    }

    [HttpGet("test")]
    public IActionResult Test()
    {
        Console.WriteLine("AccessToken: " + Request.Cookies["AccessToken"]);
        Console.WriteLine("RefreshToken: " + Request.Cookies["RefreshToken"]);

        if (Request.Cookies.TryGetValue("AccessToken", out var accessToken) &&
            Request.Cookies.TryGetValue("RefreshToken", out var refreshToken))
        {
            return Ok(new
            {
                Message = "Cookies received successfully!",
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        return BadRequest("Cookies not received.");
    }

    [HttpPost("refresh")]
    public IActionResult RefreshToken()
    {
        if (Request.Cookies.TryGetValue("RefreshToken", out var refreshToken))
        {
            var principal = ValidateToken(refreshToken);
            if (principal != null)
            {
                var username = principal.Identity?.Name;
                var newAccessToken = GenerateToken(username, 5);

                Response.Cookies.Append("AccessToken", newAccessToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,
                    SameSite = SameSiteMode.Lax,
                    Domain = ".mundial.mat"
                });

                return Ok(new { Message = "Token refreshed" });
            }
        }

        return Unauthorized("Invalid refresh token");
    }

    private string GenerateToken(string username, int minutes)
    {
        var claims = new[] { new Claim(ClaimTypes.Name, username) };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "http://api.mundial.mat:5122",
            audience: "http://api.mundial.mat:5122",
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(minutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private ClaimsPrincipal? ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "http://api.mundial.mat:5122",
                ValidAudience = "http://api.mundial.mat:5122",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey))
            }, out _);

            return principal;
        }
        catch
        {
            return null;
        }
    }
}


