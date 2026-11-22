using System.Security.Claims;
using Grpc.AspNetCore.Server;
using Grpc.Core;

namespace src.Server.Security;

public static class CallContextExtensions
{
    public static Guid GetUserId(this ServerCallContext context) => Guid.Parse(Require(context, ClaimTypes.NameIdentifier));

    public static string GetLogin(this ServerCallContext context) => Require(context, ClaimTypes.Name);

    public static Guid GetSessionId(this ServerCallContext context) => Guid.Parse(Require(context, SessionAuthenticationHandler.SessionIdClaim));

    private static string Require(ServerCallContext context, string claimType) => context.GetHttpContext().User.FindFirstValue(claimType)
        ?? throw new RpcException(new Status(StatusCode.Unauthenticated, "Authorization required"));
}
