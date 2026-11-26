namespace src.Server.Data.Entities;

public sealed class User
{
    public Guid Id { get; init; } = Guid.CreateVersion7();
    
    public required string Login { get; set; }
    public required string LoginNormalized { get; set; }
    public required byte[] PasswordHash { get; set; }
    public required byte[] PasswordSalt { get; set; }
    public required int PasswordIterations { get; set; }
    public DateTime CreatedAtUtc { get; init; }
}
