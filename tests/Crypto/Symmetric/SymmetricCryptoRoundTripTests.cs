using src.Crypto.Symmetric;
using src.Crypto.Symmetric.Abstractions;
using src.Crypto.Symmetric.Algorithms.RC5;
using src.Crypto.Symmetric.Algorithms.Twofish;
using Xunit;

namespace CipherMessenger.Tests.Crypto.Symmetric;

public sealed class SymmetricCryptoRoundTripTests
{
    public static IEnumerable<object[]> AllModePaddingPairs =>
        from mode in Enum.GetValues<CipherMode>()
        from padding in Enum.GetValues<PaddingMode>()
        select new object[] { mode, padding };

    private static readonly byte[] PlainText =
        Enumerable.Range(1, 37).Select(x => (byte)x).ToArray();

    [Theory]
    [MemberData(nameof(AllModePaddingPairs))]
    public void RC5_ShouldRoundTrip_ForEveryModeAndPadding(
        CipherMode mode,
        PaddingMode padding)
    {
        var key = new byte[16];
        var iv = Enumerable.Repeat((byte)1, 8).ToArray();

        AssertRoundTrip(
            () => new RC5Cipher(32, 12, 16),
            key,
            iv,
            mode,
            padding);
    }

    [Theory]
    [MemberData(nameof(AllModePaddingPairs))]
    public void Twofish_ShouldRoundTrip_ForEveryModeAndPadding(
        CipherMode mode,
        PaddingMode padding)
    {
        var key = new byte[16];
        var iv = Enumerable.Repeat((byte)1, 16).ToArray();

        AssertRoundTrip(
            () => new TwofishCipher(),
            key,
            iv,
            mode,
            padding);
    }

    private static void AssertRoundTrip<TCipher>(
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

        context.Encrypt(PlainText, out var encrypted);
        context.Decrypt(encrypted, out var decrypted);

        Assert.NotEmpty(encrypted);
        Assert.Equal(PlainText, decrypted);
    }
}
