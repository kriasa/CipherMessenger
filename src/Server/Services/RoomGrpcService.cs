using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using src.Contracts;
using src.Server.Data;
using src.Server.Data.Entities;
using src.Server.Security;

namespace src.Server.Services;

public sealed class RoomGrpcService(
    ChatDbContext db,
    RoomLifecycle lifecycle,
    TimeProvider time,
    ILogger<RoomGrpcService> logger) : RoomService.RoomServiceBase
{
    public override async Task<RoomInfo> CreateRoom(CreateRoomRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;

        var peerId = ParseId(request.PeerUserId, "peer_user_id");
        if (peerId == me) throw Invalid("You can't create a chat with yourself.");

        CipherSettingsValidator.Validate(request.Cipher);
        var (dhPrime, dhGenerator) = DhValidator.ValidateParameters(request.Dh);

        var (a, b) = ContactLink.OrderPair(me, peerId);
        var isContact = await db.ContactLinks.AsNoTracking().AnyAsync(c => c.UserAId == a && c.UserBId == b && c.Status == ContactLinkStatus.Accepted, ct);
        if (!isContact) throw new RpcException(new Status(StatusCode.FailedPrecondition,"A secret chat can only be created with a verified contact."));

        var cipher = request.Cipher;
        var (algorithm, keySize, wordBits, rounds) = ExtractAlgorithm(cipher);
        var room = new Room
        {
            CreatorId = me,
            Status = RoomStatus.Open,
            Algorithm = algorithm,
            Mode = cipher.Mode,
            Padding = cipher.Padding,
            KeySizeBytes = keySize,
            Rc5WordBits = wordBits,
            Rc5Rounds = rounds,
            DhPrime = dhPrime,
            DhGenerator = dhGenerator,
            CreatedAtUtc = time.GetUtcNow().UtcDateTime,
            Members =
            {
                new RoomMember { UserId = me },
                new RoomMember { UserId = peerId }
            }
        };
        db.Rooms.Add(room);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("A room has been created {Room}: {Creator} и {Peer}, {Algorithm}/{Mode}/{Padding}", room.Id, me, peerId, room.Algorithm, room.Mode, room.Padding);
        return ToInfo(await LoadAsync(room.Id, me, ct), me);
    }

    public override async Task<RoomInfo> JoinRoom(RoomIdRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;

        var room = await LoadAsync(ParseId(request.RoomId, "room_id"), me, ct);
        if (room.Status != RoomStatus.Open) throw new RpcException(new Status(StatusCode.FailedPrecondition, "The room is closed"));

        var now = time.GetUtcNow().UtcDateTime;
        await db.RoomMembers.Where(m => m.RoomId == room.Id && m.UserId == me).ExecuteUpdateAsync(s => s
            .SetProperty(m => m.IsConnected, true)
            .SetProperty(m => m.JoinedAtUtc, (DateTime?)now), ct);

        return ToInfo(await LoadAsync(room.Id, me, ct), me);
    }

    public override async Task<LeaveRoomReply> LeaveRoom(RoomIdRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;

        var room = await LoadAsync(ParseId(request.RoomId, "room_id"), me, ct);
        var now = time.GetUtcNow().UtcDateTime;
        await db.RoomMembers
            .Where(m => m.RoomId == room.Id && m.UserId == me && m.IsConnected)
            .ExecuteUpdateAsync(s => s
                .SetProperty(m => m.IsConnected, false)
                .SetProperty(m => m.LeftAtUtc, (DateTime?)now), ct);

        return new LeaveRoomReply();
    }

    public override async Task<CloseRoomReply> CloseRoom(RoomIdRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;
        var room = await LoadAsync(ParseId(request.RoomId, "room_id"), me, ct);
        await lifecycle.CloseAsync([room.Id], ct);
        return new CloseRoomReply();
    }
    public override async Task<RoomInfo> SubmitDhPublic(SubmitDhPublicRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;

        var room = await LoadAsync(ParseId(request.RoomId, "room_id"), me, ct);
        if (room.Status != RoomStatus.Open) throw new RpcException(new Status(StatusCode.FailedPrecondition, "The room is closed"));
        if (request.KeyEpoch != (uint)room.KeyEpoch) throw new RpcException(new Status(StatusCode.FailedPrecondition,"Update the room state and repeat"));

        var publicValue = DhValidator.ValidatePublicValue(request.PublicValue, room.DhPrime);
        var epoch = room.KeyEpoch;

        var updated = await db.RoomMembers
            .Where(m => m.RoomId == room.Id && m.UserId == me && m.DhPublicValue == null && m.Room.KeyEpoch == epoch  && m.Room.Status == RoomStatus.Open)
            .ExecuteUpdateAsync(s => s.SetProperty(m => m.DhPublicValue, publicValue), ct);

        if (updated == 0)
        {
            var current = await LoadAsync(room.Id, me, ct);
            var alreadySent = current.KeyEpoch == epoch && current.Members.First(m => m.UserId == me).DhPublicValue is not null;
            throw alreadySent
                ? new RpcException(new Status(StatusCode.AlreadyExists, "You have already submitted an open value in this era"))
                : new RpcException(new Status(StatusCode.Aborted, "The state of the room has changed; please repeat your request"));
        }

        return ToInfo(await LoadAsync(room.Id, me, ct), me);
    }

    public override async Task<RoomInfo> RestartKeyExchange(RoomIdRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var ct = context.CancellationToken;

        var room = await LoadAsync(ParseId(request.RoomId, "room_id"), me, ct);
        if (room.Status != RoomStatus.Open)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "The room is closed"));

        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            await db.Rooms
                .Where(r => r.Id == room.Id && r.Status == RoomStatus.Open)
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.KeyEpoch, r => r.KeyEpoch + 1), ct);

            await db.RoomMembers
                .Where(m => m.RoomId == room.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(m => m.DhPublicValue, (byte[]?)null), ct);

            await tx.CommitAsync(ct);
        }

        logger.LogInformation("Key exchange has been restarted in the room {Room}, {User}", room.Id, me);
        return ToInfo(await LoadAsync(room.Id, me, ct), me);
    }
    public override async Task<RoomInfo> GetRoom(RoomIdRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var room = await LoadAsync(ParseId(request.RoomId, "room_id"), me, context.CancellationToken);
        return ToInfo(room, me);
    }

    public override async Task<ListRoomsReply> ListRooms(ListRoomsRequest request, ServerCallContext context)
    {
        var me = context.GetUserId();
        var includeClosed = request.IncludeClosed;

        var rooms = await db.Rooms
            .AsNoTracking()
            .Include(r => r.Members).ThenInclude(m => m.User)
            .Where(r => r.Members.Any(m => m.UserId == me) && (includeClosed || r.Status == RoomStatus.Open))
            .OrderByDescending(r => r.CreatedAtUtc)
            .ToListAsync(context.CancellationToken);

        var reply = new ListRoomsReply();
        reply.Rooms.AddRange(rooms.Select(r => ToInfo(r, me)));
        return reply;
    }
    private async Task<Room> LoadAsync(Guid roomId, Guid me, CancellationToken ct)
    {
        var room = await db.Rooms
            .AsNoTracking()
            .Include(r => r.Members).ThenInclude(m => m.User)
            .FirstOrDefaultAsync(r => r.Id == roomId && r.Members.Any(m => m.UserId == me), ct);
        return room ?? throw new RpcException(new Status(StatusCode.NotFound, "Room not found"));
    }

    private static RoomInfo ToInfo(Room room, Guid me)
    {
        var mine = room.Members.First(m => m.UserId == me);
        var peer = room.Members.First(m => m.UserId != me);

        var info = new RoomInfo
        {
            RoomId = room.Id.ToString(),
            State = room.Status == RoomStatus.Open ? RoomState.Open : RoomState.Closed,
            Cipher = ToSettings(room),
            CreatorUserId = room.CreatorId.ToString(),
            Dh = new RoomDhParameters
            {
                P = ByteString.CopyFrom(room.DhPrime),
                G = ByteString.CopyFrom(room.DhGenerator)
            },
            KeyEpoch = (uint)room.KeyEpoch,
            Me = ToMember(mine),
            Peer = ToMember(peer),
            CreatedAtUtc = ToTimestamp(room.CreatedAtUtc)
        };
        if (room.ClosedAtUtc is { } closed) info.ClosedAtUtc = ToTimestamp(closed);
        return info;
    }
    private static (RoomAlgorithm Algorithm, int KeySize, int? WordBits, int? Rounds) ExtractAlgorithm(CipherSettings c)
        => c.AlgorithmParametersCase switch
        {
            CipherSettings.AlgorithmParametersOneofCase.Rc5 => (RoomAlgorithm.Rc5, (int)c.Rc5.KeySizeBytes, (int)c.Rc5.WordSizeBits, (int)c.Rc5.Rounds),
            CipherSettings.AlgorithmParametersOneofCase.Twofish => (RoomAlgorithm.Twofish, (int)c.Twofish.KeySizeBytes, null, null),
            _ => throw Invalid("No encryption algorithm selected")
        };

    private static CipherSettings ToSettings(Room room)
    {
        var settings = new CipherSettings { Mode = room.Mode, Padding = room.Padding };
        switch (room.Algorithm)
        {
            case RoomAlgorithm.Rc5:
                settings.Rc5 = new Rc5Settings
                {
                    KeySizeBytes = (uint)room.KeySizeBytes,
                    WordSizeBits = (uint)(room.Rc5WordBits ?? 0),
                    Rounds = (uint)(room.Rc5Rounds ?? 0)
                };
                break;
            case RoomAlgorithm.Twofish:
                settings.Twofish = new TwofishSettings { KeySizeBytes = (uint)room.KeySizeBytes };
                break;
        }
        return settings;
    }
    private static RoomMemberInfo ToMember(RoomMember m) => new()
    {
        UserId = m.UserId.ToString(),
        Login = m.User.Login,
        Connected = m.IsConnected
    };
    private static Timestamp ToTimestamp(DateTime utc) => Timestamp.FromDateTime(DateTime.SpecifyKind(utc, DateTimeKind.Utc));
    private static Guid ParseId(string? value, string field) => Guid.TryParse(value, out var id) ? id : throw Invalid($"Invalid field value {field}");
    private static RpcException Invalid(string message) => new(new Status(StatusCode.InvalidArgument, message));
}
