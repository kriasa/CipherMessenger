using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using src.Server.Configuration;

namespace src.Server.Data;

public static class DatabaseInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken ct = default)
    {
        using var scope = services.CreateScope();
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("DatabaseInitializer");
        var options = scope.ServiceProvider.GetRequiredService<IOptions<DatabaseOptions>>().Value;
        var db = scope.ServiceProvider.GetRequiredService<ChatDbContext>();

        for (var attempt = 1; ; ++attempt)
        {
            try
            {
                if (options.EnsureCreatedOnStartup) await db.Database.EnsureCreatedAsync(ct);
                else if (!await db.Database.CanConnectAsync(ct)) throw new InvalidOperationException("Database unavailable");

                logger.LogInformation("Database is ready");
                return;
            }
            catch (Exception ex) when (attempt < options.StartupRetries && !ct.IsCancellationRequested)
            {
                logger.LogWarning("Database unavailable ({Attempt}/{Max}): {Message}", attempt, options.StartupRetries, ex.GetBaseException().Message);
                await Task.Delay(TimeSpan.FromSeconds(options.StartupRetryDelaySeconds), ct);
            }
        }
    }
}
