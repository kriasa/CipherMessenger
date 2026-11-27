using src.Contracts;

namespace src.Server.Data.Entities;

public enum RoomStatus
{
    Open = 0,
    Closed = 1
}

public enum RoomAlgorithm
{
    Rc5 = 1,
    Twofish = 2
}

public sealed class Room
{
    public Guid Id { get; init; } = Guid.CreateVersion7();

    public Guid CreatorId { get; init; }
    public RoomStatus Status { get; set; }
    public RoomAlgorithm Algorithm { get; init; }
    public RoomCipherMode Mode { get; init; }
    public RoomPaddingMode Padding { get; init; }
    public int KeySizeBytes { get; init; }
    public int? Rc5WordBits { get; init; }
    public int? Rc5Rounds { get; init; }
    public required byte[] DhPrime { get; init; }
    public required byte[] DhGenerator { get; init; }
    public int KeyEpoch { get; set; } = 1;
    public DateTime CreatedAtUtc { get; init; }
    public DateTime? ClosedAtUtc { get; set; }
    public List<RoomMember> Members { get; init; } = [];
}

public sealed class RoomMember
{
    public Guid RoomId { get; init; }
    public Room Room { get; init; } = null!;
    public Guid UserId { get; init; }
    public User User { get; init; } = null!;
    public bool IsConnected { get; set; }
    public byte[]? DhPublicValue { get; set; }
    public DateTime? JoinedAtUtc { get; set; }
    public DateTime? LeftAtUtc { get; set; }
}
