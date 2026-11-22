using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace src.Server.Security;

public static class SessionTokens
{
    private const int TokenBytes = 32;
    public static string Generate() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(TokenBytes));
    public static byte[] Hash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));
}
