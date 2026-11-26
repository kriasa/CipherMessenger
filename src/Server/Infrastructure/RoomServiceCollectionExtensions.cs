using src.Server.Services;

namespace src.Server.Infrastructure;

public static class RoomServiceCollectionExtensions
{
    public static IServiceCollection AddRoomServices(this IServiceCollection services)
    {
        services.AddScoped<RoomLifecycle>();
        return services;
    }
}
