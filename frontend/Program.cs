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

#if DEBUG
    var url = "http://localhost:80";
#else
    var url = "http://0.0.0.0:80";
#endif

Console.WriteLine($"Фронтенд запущен на {url}");
app.Run(url);