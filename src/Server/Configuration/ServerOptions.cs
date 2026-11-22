using System.ComponentModel.DataAnnotations;

namespace src.Server.Configuration;

public sealed class DatabaseOptions
{
    public const string Section = "Database";
    public bool EnsureCreatedOnStartup { get; set; } = true;

    [Range(1, 100)]
    public int StartupRetries { get; set; } = 10;

    [Range(1, 60)]
    public int StartupRetryDelaySeconds { get; set; } = 2;
}

public sealed class RabbitMqOptions
{
    public const string Section = "RabbitMq";

    [Required] 
    public string HostName { get; set; } = "localhost";
    [Range(1, 65535)] 
    public int Port { get; set; } = 5672;
    [Required] 
    public string UserName { get; set; } = "";
    [Required] 
    public string Password { get; set; } = "";
    [Required] 
    public string VirtualHost { get; set; } = "/";

    [Range(1, 525600)]
    public int QueueExpiresMinutes { get; set; } = 10080;

    [Range(1, 1000)]
    public ushort Prefetch { get; set; } = 16;
}

public sealed class LimitsOptions
{
    public const string Section = "Limits";

    [Range(1024, 64 * 1024 * 1024)]
    public int MaxFragmentBytes { get; set; } = 1024 * 1024;

    [Range(0, 1024 * 1024)]
    public int MessageOverheadBytes { get; set; } = 64 * 1024;

    [Range(1, 24 * 365)]
    public int SessionHours { get; set; } = 24;
}
public sealed class SecurityOptions
{
    public const string Section = "Security";

    [Range(100_000, 10_000_000)]
    public int Pbkdf2Iterations { get; set; } = 600_000;
}
