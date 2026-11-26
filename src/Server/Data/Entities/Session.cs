namespace src.Server.Data.Entities;

public sealed class Session
{
    public Guid Id { get; init; } = Guid.CreateVersion7();

    public Guid UserId { get; init; }
    public User User { get; init; } = null!;
    public required byte[] TokenHash { get; init; }
    public DateTime CreatedAtUtc { get; init; }
    public DateTime ExpiresAtUtc { get; init; }
    public DateTime? RevokedAtUtc { get; set; }
}
