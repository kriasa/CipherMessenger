using src.Server.Data;
using src.Server.Infrastructure;
using src.Server.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddServerOptions(builder.Configuration)
    .AddPersistence(builder.Configuration)
    .AddServerAuth()
    .AddServerGrpc(builder.Environment);

var app = builder.Build();

await DatabaseInitializer.InitializeAsync(app.Services, app.Lifetime.ApplicationStopping);

app.UseAuthentication();
app.UseAuthorization();

app.MapGrpcService<ServerInfoGrpcService>();
app.MapGrpcService<AuthGrpcService>();
if (app.Environment.IsDevelopment()) app.MapGrpcReflectionService().AllowAnonymous();

app.Run();
