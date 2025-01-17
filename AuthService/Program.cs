using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngularApp", policy =>
    {
        policy.WithOrigins("http://cliente01.mundial.mat:4200", "http://cliente02.mundial.mat:4300") // Origem permitida
              .AllowAnyMethod()                   // Permite GET, POST, etc.
              .AllowAnyHeader()                   // Permite todos os cabeçalhos
              .AllowCredentials();                // Permite cookies e credenciais
    });
});
builder.Services.AddControllers();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true, // Verifica se o emissor do token é válido
            ValidateAudience = true, // Verifica se o público do token é válido
            ValidateLifetime = true, // Verifica se o token está dentro do período de validade
            ValidateIssuerSigningKey = true, // Valida a chave de assinatura usada para gerar o token
            ValidIssuer = "http://api.mundial.mat:5122", // URL do emissor esperado (AuthService)
            ValidAudience = "http://api.mundial.mat:5122", // Público esperado para o token
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SuperSecretKey123SuperSecretKey123")) // Chave usada para validar o token
        };
    }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Minha API",
        Version = "v1",
        Description = "Exemplo de autenticação com JWT no Swagger"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Insira o token JWT no formato: Bearer {seu_token}"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Minha API v1");
    });
}
app.UseCors("AllowAngularApp");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
