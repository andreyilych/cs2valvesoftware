// Program.cs
using Backend;
using Backend.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<DnsCheckerService>();
builder.Services.AddCors();

var app = builder.Build();

app.UseCors(policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
app.MapControllers();

app.Use(async (context, next) =>
{
    await next();
    if (context.Response.StatusCode == 404 && !context.Response.HasStarted)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { error = "Endpoint not found" });
    }
});

#if DEBUG
var url = "http://localhost:5000";
#else
var url = "http://0.0.0.0:5000";
#endif

Console.WriteLine($"Backend running on {url}");
app.Run(url);