using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using src.Server.Data;

namespace src.Server.Security;

public sealed class SessionAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    ChatDbContext db,
    TimeProvider time)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    public const string SchemeName = "Session";
    public const string SessionIdClaim = "session_id";
    private const string BearerPrefix = "Bearer ";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var header)) return AuthenticateResult.NoResult();

        var value = header.ToString();
        if (!value.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase)) return AuthenticateResult.NoResult();

        var token = value[BearerPrefix.Length..].Trim();
        if (token.Length == 0) return AuthenticateResult.Fail("Empty token");

        var hash = SessionTokens.Hash(token);
        var session = await db.Sessions
            .AsNoTracking()
            .Where(s => s.TokenHash == hash)
            .Select(s => new { s.Id, s.UserId, s.User.Login, s.ExpiresAtUtc, s.RevokedAtUtc })
            .FirstOrDefaultAsync(Context.RequestAborted);

        var now = time.GetUtcNow().UtcDateTime;
        if (session is null || session.RevokedAtUtc is not null || session.ExpiresAtUtc <= now) return AuthenticateResult.Fail("Invalid or expired session");

        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, session.UserId.ToString()),
            new Claim(ClaimTypes.Name, session.Login),
            new Claim(SessionIdClaim, session.Id.ToString())
        ], SchemeName);

        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return AuthenticateResult.Success(ticket);
    }
}
