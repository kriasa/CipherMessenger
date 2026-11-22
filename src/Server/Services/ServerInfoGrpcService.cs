using System.Reflection;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using src.Contracts;
using src.Server.Data;

namespace src.Server.Services;

public sealed class ServerInfoGrpcService(ChatDbContext db) : ServerInfoService.ServerInfoServiceBase
{
    private static readonly string Version =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";

    public override async Task<GetInfoReply> GetInfo(GetInfoRequest request, ServerCallContext context)
    {
        var dbOk = false;
        try 
        { 
            dbOk = await db.Database.CanConnectAsync(context.CancellationToken); 
        }
        catch (Exception) when (!context.CancellationToken.IsCancellationRequested) { }

        return new GetInfoReply
        {
            Version = Version,
            ServerTimeUtc = Timestamp.FromDateTime(DateTime.UtcNow),
            DatabaseAvailable = dbOk
        };
    }
}
