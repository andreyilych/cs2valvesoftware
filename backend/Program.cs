using Backend.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<DnsCheckerService>();

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

app.MapControllers();

// Обработчик 404 для всего остального
app.Use(async (context, next) =>
{
    await next();

    if (context.Response.StatusCode == 404 && !context.Response.HasStarted)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new
        {
            error = "HELLO WORLD MOTHER FUCKER COUNTER STRIKE 2 ",
        });
    }
});


#if DEBUG
var url = "http://localhost:5000";
#else
    var url = "http://0.0.0.0:5000";
#endif

Console.WriteLine($"Бекенд запущен на {url}");
app.Run(url);