using Grpc.AspNetCore.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using src.Server.Configuration;
using src.Server.Data;
using src.Server.Security;

namespace src.Server.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddServerOptions(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddValidatedOptions<DatabaseOptions>(configuration, DatabaseOptions.Section);
        services.AddValidatedOptions<RabbitMqOptions>(configuration, RabbitMqOptions.Section);
        services.AddValidatedOptions<LimitsOptions>(configuration, LimitsOptions.Section);
        services.AddValidatedOptions<SecurityOptions>(configuration, SecurityOptions.Section);
        return services;
    }

    public static IServiceCollection AddPersistence(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("Connection string not specified - ConnectionStrings:Postgres");

        services.AddDbContext<ChatDbContext>(o => o.UseNpgsql(connectionString));
        return services;
    }
    public static IServiceCollection AddServerAuth(this IServiceCollection services)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<PasswordHasher>();

        services.AddAuthentication(SessionAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, SessionAuthenticationHandler>(SessionAuthenticationHandler.SchemeName, _ => { });

        services.AddAuthorization(o =>
            o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
        return services;
    }

    public static IServiceCollection AddServerGrpc(this IServiceCollection services, IHostEnvironment environment)
    {
        services.AddGrpc();

        services.AddOptions<GrpcServiceOptions>()
            .Configure<IOptions<LimitsOptions>>((grpc, limits) =>
            {
                var max = limits.Value.MaxFragmentBytes + limits.Value.MessageOverheadBytes;
                grpc.MaxReceiveMessageSize = max;
                grpc.MaxSendMessageSize = max;
            });

        if (environment.IsDevelopment()) services.AddGrpcReflection();
        return services;
    }

    private static void AddValidatedOptions<T>(this IServiceCollection services, IConfiguration configuration, string section)
        where T : class
    {
        services.AddOptions<T>().Bind(configuration.GetSection(section)).ValidateDataAnnotations().ValidateOnStart();
    }
}
