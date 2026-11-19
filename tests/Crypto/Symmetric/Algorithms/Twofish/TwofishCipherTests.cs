using src.Crypto.Symmetric.Algorithms.Twofish;

namespace CipherMessenger.Tests.Crypto.Algorithms.Twofish;

public sealed class TwofishCipherTests
{
    public static IEnumerable<object[]> OfficialTestVectors =>
    [
        [
            new string('0', 32),
            new string('0', 32),
            "9F589F5CF6122C32B6BFEC2F2AE8C35A"
        ],
        [
            new string('0', 48),
            new string('0', 32),
            "EFA71F788965BD4453F860178FC19101"
        ],
        [
            new string('0', 64),
            new string('0', 32),
            "57FF739D4DC92C1BD7FC01700CC8216F"
        ]
    ];

    [Fact]
    public void BlockSize_ShouldBe16Bytes()
    {
        var cipher = new TwofishCipher();

        Assert.Equal(16, cipher.BlockSize);
    }

    [Theory]
    [MemberData(nameof(OfficialTestVectors))]
    public void Encrypt_ShouldMatchOfficialTestVector(
        string keyHex,
        string plaintextHex,
        string expectedCiphertextHex)
    {
        var cipher = new TwofishCipher();

        cipher.SetKey(Convert.FromHexString(keyHex));

        var plaintext = Convert.FromHexString(plaintextHex);
        var expected = Convert.FromHexString(expectedCiphertextHex);

        var actual = cipher.Encrypt(plaintext);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [MemberData(nameof(OfficialTestVectors))]
    public void Decrypt_ShouldMatchOfficialTestVector(
        string keyHex,
        string plaintextHex,
        string ciphertextHex)
    {
        var cipher = new TwofishCipher();

        cipher.SetKey(Convert.FromHexString(keyHex));

        var ciphertext = Convert.FromHexString(ciphertextHex);
        var expected = Convert.FromHexString(plaintextHex);

        var actual = cipher.Decrypt(ciphertext);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void EncryptAndDecrypt_ShouldRestoreOriginalBlock(int keySize)
    {
        var cipher = new TwofishCipher();

        var key = Enumerable.Range(0, keySize)
            .Select(i => (byte)(i * 7 + 1))
            .ToArray();

        var plaintext = Enumerable.Range(0, 16)
            .Select(i => (byte)(i * 13 + 5))
            .ToArray();

        cipher.SetKey(key);

        var ciphertext = cipher.Encrypt(plaintext);
        var decrypted = cipher.Decrypt(ciphertext);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void SetKey_ShouldThrowArgumentNullException_WhenKeyIsNull()
    {
        var cipher = new TwofishCipher();

        Assert.Throws<ArgumentNullException>(
            () => cipher.SetKey(null!));
    }

    [Fact]
    public void SetKey_ShouldThrowArgumentException_WhenKeyIsTooLong()
    {
        var cipher = new TwofishCipher();

        Assert.Throws<ArgumentException>(
            () => cipher.SetKey(new byte[33]));
    }

    [Fact]
    public void Encrypt_ShouldThrowArgumentNullException_WhenBlockIsNull()
    {
        var cipher = new TwofishCipher();
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentNullException>(
            () => cipher.Encrypt(null!));
    }

    [Fact]
    public void Decrypt_ShouldThrowArgumentNullException_WhenBlockIsNull()
    {
        var cipher = new TwofishCipher();
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentNullException>(
            () => cipher.Decrypt(null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(32)]
    public void Encrypt_ShouldThrowArgumentException_WhenBlockHasIncorrectLength(
        int blockSize)
    {
        var cipher = new TwofishCipher();
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentException>(
            () => cipher.Encrypt(new byte[blockSize]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(32)]
    public void Decrypt_ShouldThrowArgumentException_WhenBlockHasIncorrectLength(
        int blockSize)
    {
        var cipher = new TwofishCipher();
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentException>(
            () => cipher.Decrypt(new byte[blockSize]));
    }

    [Fact]
    public void Encrypt_ShouldThrowInvalidOperationException_WhenKeyIsNotSet()
    {
        var cipher = new TwofishCipher();

        Assert.Throws<InvalidOperationException>(
            () => cipher.Encrypt(new byte[16]));
    }

    [Fact]
    public void Decrypt_ShouldThrowInvalidOperationException_WhenKeyIsNotSet()
    {
        var cipher = new TwofishCipher();

        Assert.Throws<InvalidOperationException>(
            () => cipher.Decrypt(new byte[16]));
    }

    [Theory]
    [InlineData(1, 16)]
    [InlineData(15, 16)]
    [InlineData(17, 24)]
    [InlineData(23, 24)]
    [InlineData(25, 32)]
    [InlineData(31, 32)]
    public void SetKey_ShouldPadShortKeysToNextSupportedSize(
        int originalSize,
        int paddedSize)
    {
        var key = Enumerable.Range(0, originalSize)
            .Select(i => (byte)(i + 1))
            .ToArray();

        var paddedKey = new byte[paddedSize];
        key.CopyTo(paddedKey, 0);

        var cipher1 = new TwofishCipher();
        var cipher2 = new TwofishCipher();

        cipher1.SetKey(key);
        cipher2.SetKey(paddedKey);

        var plaintext = new byte[16];

        Assert.Equal(
            cipher2.Encrypt(plaintext),
            cipher1.Encrypt(plaintext));
    }
}
