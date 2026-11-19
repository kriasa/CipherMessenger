using src.Crypto.Symmetric;
using src.Crypto.Symmetric.Abstractions;
using src.Crypto.Symmetric.Algorithms.RC5;
using src.Crypto.Symmetric.Algorithms.Twofish;
using Xunit;

namespace CipherMessenger.Tests.Crypto.Symmetric;

public sealed class SymmetricCryptoAsyncTests
{
    public static IEnumerable<object[]> AllModePaddingPairs =>
        from mode in Enum.GetValues<CipherMode>()
        from padding in Enum.GetValues<PaddingMode>()
        select new object[] { mode, padding };

    private static readonly byte[] PlainText =
        Enumerable.Range(1, 37).Select(x => (byte)x).ToArray();

    [Theory]
    [MemberData(nameof(AllModePaddingPairs))]
    public async Task RC5_AsyncMethods_ShouldRoundTrip(
        CipherMode mode,
        PaddingMode padding)
    {
        await AssertAsyncRoundTrip(
            () => new RC5Cipher(32, 12, 16),
            new byte[16],
            Enumerable.Repeat((byte)1, 8).ToArray(),
            mode,
            padding);
    }

    [Theory]
    [MemberData(nameof(AllModePaddingPairs))]
    public async Task Twofish_AsyncMethods_ShouldRoundTrip(
        CipherMode mode,
        PaddingMode padding)
    {
        await AssertAsyncRoundTrip(
            () => new TwofishCipher(),
            new byte[16],
            Enumerable.Repeat((byte)1, 16).ToArray(),
            mode,
            padding);
    }

    private static async Task AssertAsyncRoundTrip<TCipher>(
        Func<TCipher> cipherFactory,
        byte[] key,
        byte[] iv,
        CipherMode mode,
        PaddingMode padding)
        where TCipher : ISymmetricCipher
    {
        var context = new SymmetricCryptoContext<TCipher>(
            cipherFactory,
            key,
            mode,
            padding,
            iv);

        byte[] encrypted = await context.EncryptAsync(PlainText);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.NotEmpty(encrypted);
        Assert.Equal(PlainText, decrypted);
    }
}
