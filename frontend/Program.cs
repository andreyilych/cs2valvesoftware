var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// Прокси для API — чтобы не думать о CORS
app.MapFallbackToFile("index.html");

Console.WriteLine("Фронтенд запущен на http://localhost:80");
app.Run("http://localhost:80");