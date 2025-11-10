var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.MapGet("/", () => Results.Ok("OK"));
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.Run();