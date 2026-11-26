using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using src.Server.Configuration;

namespace src.Server.Security;

public sealed class PasswordHasher(IOptions<SecurityOptions> options)
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private static readonly byte[] DummySalt = new byte[SaltSize];
    private static readonly byte[] DummyHash = new byte[HashSize];

    public (byte[] Hash, byte[] Salt, int Iterations) Hash(string password)
    {
        var iterations = options.Value.Pbkdf2Iterations;
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Derive(password, salt, iterations);
        return (hash, salt, iterations);
    }
    public bool Verify(string password, byte[] salt, int iterations, byte[] expectedHash)
    {
        var actual = Derive(password, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }
    public void BurnTime(string password) => Derive(password, DummySalt, options.Value.Pbkdf2Iterations);
    private static byte[] Derive(string password, byte[] salt, int iterations) => Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashSize);
}
