using src.Crypto.Symmetric.Algorithms.Twofish;

namespace CipherMessenger.Tests.Crypto.Algorithms.Twofish;

public class TwofishArbitraryKeyLengthTests
{
    [Theory]
    [MemberData(nameof(KeyLengths))]
    public void SetKey_ShouldPadKeyToNextAllowedSize(
        int keyLength,
        int expectedLength)
    {
        // Arrange
        byte[] key = Enumerable.Range(0, keyLength)
            .Select(i => (byte)(i * 17 + 3))
            .ToArray();

        byte[] paddedKey = new byte[expectedLength];
        Array.Copy(key, paddedKey, key.Length);

        byte[] plaintext = Enumerable.Range(0, 16)
            .Select(i => (byte)(i * 11 + 1))
            .ToArray();

        var cipherWithShortKey = new TwofishCipher();
        var cipherWithPaddedKey = new TwofishCipher();

        // Act
        cipherWithShortKey.SetKey(key);
        cipherWithPaddedKey.SetKey(paddedKey);

        byte[] actual = cipherWithShortKey.Encrypt(plaintext);
        byte[] expected = cipherWithPaddedKey.Encrypt(plaintext);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void SetKey_ShouldRejectKeyLongerThan256Bits()
    {
        var cipher = new TwofishCipher();
        byte[] key = new byte[33];

        Assert.Throws<ArgumentException>(() => cipher.SetKey(key));
    }

    [Fact]
    public void SetKey_ShouldRejectEmptyKey()
    {
        var cipher = new TwofishCipher();
        byte[] key = [];

        Assert.Throws<ArgumentException>(() => cipher.SetKey(key));
    }

    public static IEnumerable<object[]> KeyLengths =>
        Enumerable.Range(1, 32)
            .Select(length => new object[]
            {
                length,
                length <= 16 ? 16 :
                length <= 24 ? 24 : 32
            });
}
