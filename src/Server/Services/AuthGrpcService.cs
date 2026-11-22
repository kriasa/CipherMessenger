using System.Text.RegularExpressions;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using src.Contracts;
using src.Server.Configuration;
using src.Server.Data;
using src.Server.Data.Entities;
using src.Server.Security;

namespace src.Server.Services;

public sealed class AuthGrpcService(
    ChatDbContext db,
    PasswordHasher hasher,
    TimeProvider time,
    IOptions<LimitsOptions> limits,
    ILogger<AuthGrpcService> logger) : AuthService.AuthServiceBase
{
    private const int MinLoginLength = 3;
    private const int MaxLoginLength = 32;
    private const int MinPasswordLength = 8;
    private const int MaxPasswordLength = 128;
    private static readonly Regex LoginFormat = new("^[A-Za-z0-9_.-]+$", RegexOptions.Compiled);

    [AllowAnonymous]
    public override async Task<RegisterReply> Register(RegisterRequest request, ServerCallContext context)
    {
        var login = request.Login ?? "";
        var password = request.Password ?? "";
        ValidateLogin(login);
        ValidatePassword(password);

        var normalized = login.ToLowerInvariant();
        var ct = context.CancellationToken;

        if (await db.Users.AnyAsync(u => u.LoginNormalized == normalized, ct))
            throw LoginTaken();

        var (hash, salt, iterations) = hasher.Hash(password);
        var user = new User
        {
            Login = login,
            LoginNormalized = normalized,
            PasswordHash = hash,
            PasswordSalt = salt,
            PasswordIterations = iterations,
            CreatedAtUtc = time.GetUtcNow().UtcDateTime
        };
        db.Users.Add(user);

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw LoginTaken();
        }

        logger.LogInformation("User registered { Login}", login);
        return new RegisterReply { UserId = user.Id.ToString(), Login = user.Login };
    }

    [AllowAnonymous]
    public override async Task<LoginReply> Login(LoginRequest request, ServerCallContext context)
    {
        var login = request.Login ?? "";
        var password = request.Password ?? "";
        if (login.Length is 0 or > MaxLoginLength || password.Length is 0 or > MaxPasswordLength) throw InvalidCredentials();

        var ct = context.CancellationToken;
        var normalized = login.ToLowerInvariant();
        var user = await db.Users.FirstOrDefaultAsync(u => u.LoginNormalized == normalized, ct);

        if (user is null)
        {
            hasher.BurnTime(password);
            throw InvalidCredentials();
        }
        if (!hasher.Verify(password, user.PasswordSalt, user.PasswordIterations, user.PasswordHash)) throw InvalidCredentials();

        var now = time.GetUtcNow().UtcDateTime;
        var expires = now.AddHours(limits.Value.SessionHours);
        var token = SessionTokens.Generate();

        await db.Sessions.Where(s => s.UserId == user.Id && s.ExpiresAtUtc < now).ExecuteDeleteAsync(ct);

        db.Sessions.Add(new Session
        {
            UserId = user.Id,
            TokenHash = SessionTokens.Hash(token),
            CreatedAtUtc = now,
            ExpiresAtUtc = expires
        });
        await db.SaveChangesAsync(ct);
        return new LoginReply
        {
            Token = token,
            ExpiresAtUtc = Timestamp.FromDateTime(expires),
            UserId = user.Id.ToString(),
            Login = user.Login
        };
    }

    public override async Task<LogoutReply> Logout(LogoutRequest request, ServerCallContext context)
    {
        var sessionId = context.GetSessionId();
        var now = time.GetUtcNow().UtcDateTime;
        await db.Sessions
            .Where(s => s.Id == sessionId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAtUtc, now), context.CancellationToken);
        return new LogoutReply();
    }

    private static void ValidateLogin(string login)
    {
        if (login.Length is < MinLoginLength or > MaxLoginLength || !LoginFormat.IsMatch(login))
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                $"Login: {MinLoginLength}–{MaxLoginLength} symbols(A-Z a-z 0-9 _ . -)"));
    }

    private static void ValidatePassword(string password)
    {
        if (password.Length is < MinPasswordLength or > MaxPasswordLength)
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                $"Password: {MinPasswordLength}–{MaxPasswordLength} symbols"));
    }
    private static RpcException LoginTaken() => new(new Status(StatusCode.AlreadyExists, "Login is already taken"));
    private static RpcException InvalidCredentials() => new(new Status(StatusCode.Unauthenticated, "Incorrect login or password"));
}
