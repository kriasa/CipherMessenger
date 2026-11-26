using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using src.Contracts;
using src.Server.Data;
using src.Server.Data.Entities;
using src.Server.Security;

namespace src.Server.Services;

public sealed class ContactGrpcService(ChatDbContext db, TimeProvider time, ILogger<ContactGrpcService> logger)
    : ContactService.ContactServiceBase
{
    public override async Task<SendContactRequestReply> SendRequest(SendContactRequestRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;
        var login = (request.Login ?? "").Trim();
        if (login.Length == 0) throw new RpcException(new Status(StatusCode.InvalidArgument, "Enter your login"));

        var normalized = login.ToLowerInvariant();
        var target = await db.Users.AsNoTracking()
            .Where(u => u.LoginNormalized == normalized)
            .Select(u => new { u.Id, u.Login })
            .FirstOrDefaultAsync(ct)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found"));

        if (target.Id == me) throw new RpcException(new Status(StatusCode.InvalidArgument, "You cannot add yourself to your contacts"));

        var (a, b) = ContactLink.OrderPair(me, target.Id);
        var existing = await db.ContactLinks.AsNoTracking()
            .Where(c => c.UserAId == a && c.UserBId == b)
            .Select(c => new { c.Status, c.RequesterId })
            .FirstOrDefaultAsync(ct);

        if (existing is not null)
        {
            throw existing switch
            {
                { Status: ContactLinkStatus.Accepted } => AlreadyExists("This user is already in your contacts"),
                { RequesterId: var r } when r == me => AlreadyExists("A request has already been sent to this user"),
                _ => new RpcException(new Status(StatusCode.FailedPrecondition, "This user has already sent you a request: please accept it"))
            };
        }
        var now = time.GetUtcNow().UtcDateTime;
        db.ContactLinks.Add(new ContactLink
        {
            UserAId = a,
            UserBId = b,
            RequesterId = me,
            Status = ContactLinkStatus.Pending,
            CreatedAtUtc = now
        });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw AlreadyExists("A connection with this user already exists");
        }
        logger.LogInformation("Contact request: {From} -> {To}", me, target.Id);
        return new SendContactRequestReply
        {
            Contact = ToInfo(target.Id, target.Login, ContactStatus.Outgoing, now)
        };
    }

    public override async Task<RespondToContactRequestReply> RespondToRequest(RespondToContactRequestRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;
        var otherId = ParseUserId(request.UserId);
        var other = await FindUserAsync(otherId, ct);
        var (a, b) = ContactLink.OrderPair(me, otherId);
        var pending = db.ContactLinks.Where(c =>
            c.UserAId == a && c.UserBId == b && c.Status == ContactLinkStatus.Pending && c.RequesterId == otherId);

        if (!request.Accept)
        {
            var deleted = await pending.ExecuteDeleteAsync(ct);
            if (deleted == 0) throw IncomingRequestNotFound();
            return new RespondToContactRequestReply();
        }

        var now = time.GetUtcNow().UtcDateTime;
        var updated = await pending.ExecuteUpdateAsync(s => s
            .SetProperty(c => c.Status, ContactLinkStatus.Accepted)
            .SetProperty(c => c.RespondedAtUtc, (DateTime?)now), ct);
        if (updated == 0) throw IncomingRequestNotFound();

        return new RespondToContactRequestReply
        {
            Contact = ToInfo(other.Id, other.Login, ContactStatus.Accepted, now)
        };
    }

    public override async Task<RemoveContactReply> RemoveContact(RemoveContactRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var otherId = ParseUserId(request.UserId);
        var (a, b) = ContactLink.OrderPair(me, otherId);
        var deleted = await db.ContactLinks
            .Where(c => c.UserAId == a && c.UserBId == b
                        && (c.Status == ContactLinkStatus.Accepted || c.RequesterId == me))
            .ExecuteDeleteAsync(context.CancellationToken);

        if (deleted == 0) throw new RpcException(new Status(StatusCode.NotFound, "Contact not found"));
        logger.LogInformation("Connection removed: {Me} x {Other}", me, otherId);
        return new RemoveContactReply();
    }

    public override async Task<ListContactsReply> ListContacts(ListContactsRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var rows = await db.ContactLinks.AsNoTracking()
            .Where(c => c.UserAId == me || c.UserBId == me)
            .Select(c => new
            {
                OtherId = c.UserAId == me ? c.UserBId : c.UserAId,
                OtherLogin = c.UserAId == me ? c.UserB.Login : c.UserA.Login,
                c.Status,
                c.RequesterId,
                c.CreatedAtUtc,
                c.RespondedAtUtc
            })
            .ToListAsync(context.CancellationToken);

        var reply = new ListContactsReply();
        foreach (var r in rows.OrderBy(r => r.OtherLogin, StringComparer.OrdinalIgnoreCase))
        {
            var (status, since) = r.Status == ContactLinkStatus.Accepted
                ? (ContactStatus.Accepted, r.RespondedAtUtc ?? r.CreatedAtUtc)
                : (r.RequesterId == me ? ContactStatus.Outgoing : ContactStatus.Incoming, r.CreatedAtUtc);

            reply.Contacts.Add(ToInfo(r.OtherId, r.OtherLogin, status, since));
        }
        return reply;
    }

    private async Task<(Guid Id, string Login)> FindUserAsync(Guid id, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking()
            .Where(u => u.Id == id)
            .Select(u => new { u.Id, u.Login })
            .FirstOrDefaultAsync(ct);
        return user is null ? throw new RpcException(new Status(StatusCode.NotFound, "User not found")) : (user.Id, user.Login);
    }

    private static Guid ParseUserId(string? value)
        => Guid.TryParse(value, out var id) ? id : throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user identifier"));

    private static ContactInfo ToInfo(Guid userId, string login, ContactStatus status, DateTime sinceUtc) => new()
    {
        UserId = userId.ToString(),
        Login = login,
        Status = status,
        SinceUtc = Timestamp.FromDateTime(DateTime.SpecifyKind(sinceUtc, DateTimeKind.Utc))
    };

    private static RpcException AlreadyExists(string message) => new(new Status(StatusCode.AlreadyExists, message));

    private static RpcException IncomingRequestNotFound() => new(new Status(StatusCode.NotFound, "Incoming request not found or already processed"));
}
