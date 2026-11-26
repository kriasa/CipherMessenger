namespace src.Server.Data.Entities;

public enum ContactLinkStatus
{
    Pending = 0,
    Accepted = 1
}
public sealed class ContactLink
{
    public Guid Id { get; init; } = Guid.CreateVersion7();

    public Guid UserAId { get; init; }
    public User UserA { get; init; } = null!;
    public Guid UserBId { get; init; }
    public User UserB { get; init; } = null!;
    public Guid RequesterId { get; init; }
    public ContactLinkStatus Status { get; set; }
    public DateTime CreatedAtUtc { get; init; }
    public DateTime? RespondedAtUtc { get; set; }
    public static (Guid A, Guid B) OrderPair(Guid x, Guid y) => x.CompareTo(y) < 0 ? (x, y) : (y, x);
}
