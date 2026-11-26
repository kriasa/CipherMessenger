using Microsoft.EntityFrameworkCore;
using src.Server.Data;
using src.Server.Data.Entities;

namespace src.Server.Services;

public sealed class RoomLifecycle(ChatDbContext db, TimeProvider time, ILogger<RoomLifecycle> logger)
{
    public async Task<int> CloseAsync(IEnumerable<Guid> roomIds, CancellationToken ct)
    {
        var ids = roomIds.Distinct().ToList();
        if (ids.Count == 0) return 0;

        var now = time.GetUtcNow().UtcDateTime;
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var closed = await db.Rooms
            .Where(r => ids.Contains(r.Id) && r.Status == RoomStatus.Open)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, RoomStatus.Closed)
                .SetProperty(r => r.ClosedAtUtc, (DateTime?)now), ct);

        await db.RoomMembers
            .Where(m => ids.Contains(m.RoomId) && m.IsConnected)
            .ExecuteUpdateAsync(s => s
                .SetProperty(m => m.IsConnected, false)
                .SetProperty(m => m.LeftAtUtc, (DateTime?)now), ct);

        await tx.CommitAsync(ct);

        if (closed > 0) logger.LogInformation("Closed rooms: {Count}", closed);
        return closed;
    }
    public async Task<int> CloseOpenRoomsBetweenAsync(Guid x, Guid y, CancellationToken ct)
    {
        var ids = await db.Rooms
            .Where(r => r.Status == RoomStatus.Open
                        && r.Members.Any(m => m.UserId == x)
                        && r.Members.Any(m => m.UserId == y))
            .Select(r => r.Id)
            .ToListAsync(ct);

        return await CloseAsync(ids, ct);
    }
}
