using Xunit;
using src.Crypto.Symmetric.Algorithms.RC5;

namespace CipherMessenger.Tests.Crypto.Symmetric.Algorithms.RC5;

public sealed class RC5CipherTests
{
    [Fact]
    public void Encrypt_ShouldMatchKnownVector_RC5_32_12_16()
    {
        // RFC 2040: RC5-32/12/16
        var key = new byte[16];
        var plaintext = new byte[8];

        byte[] expectedCiphertext =
        {
            0x21, 0xA5, 0xDB, 0xEE,
            0x15, 0x4B, 0x8F, 0x6D
        };

        var cipher = new RC5Cipher(32, 12, 16);
        cipher.SetKey(key);

        var actual = cipher.Encrypt(plaintext);

        Assert.Equal(expectedCiphertext, actual);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void Decrypt_ShouldRestoreOriginalBlock(int w)
    {
        var parameters = new RC5Parameters(w, 12, 16);
        var key = Enumerable.Range(0, 16)
            .Select(i => (byte)i)
            .ToArray();

        var plaintext = Enumerable.Range(0, parameters.BlockSize)
            .Select(i => (byte)(i * 7 + 3))
            .ToArray();

        var cipher = new RC5Cipher(w, 12, 16);
        cipher.SetKey(key);

        var ciphertext = cipher.Encrypt(plaintext);
        var decrypted = cipher.Decrypt(ciphertext);

        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void Encrypt_ShouldReturnBlockOfCorrectSize(int w)
    {
        var parameters = new RC5Parameters(w, 12, 16);
        var cipher = new RC5Cipher(w, 12, 16);

        cipher.SetKey(new byte[16]);

        var result = cipher.Encrypt(new byte[parameters.BlockSize]);

        Assert.Equal(parameters.BlockSize, result.Length);
    }

    [Fact]
    public void Encrypt_ShouldProduceDifferentResultsForDifferentKeys()
    {
        var cipher = new RC5Cipher(32, 12, 16);
        var plaintext = new byte[8];

        cipher.SetKey(new byte[16]);
        var ciphertext1 = cipher.Encrypt(plaintext);

        var secondKey = new byte[16];
        secondKey[0] = 1;

        cipher.SetKey(secondKey);
        var ciphertext2 = cipher.Encrypt(plaintext);

        Assert.False(ciphertext1.SequenceEqual(ciphertext2));
    }

    [Fact]
    public void Encrypt_ShouldProduceDifferentResultsForDifferentBlocks()
    {
        var cipher = new RC5Cipher(32, 12, 16);
        cipher.SetKey(new byte[16]);

        var block1 = new byte[8];
        var block2 = new byte[8];
        block2[0] = 1;

        var ciphertext1 = cipher.Encrypt(block1);
        var ciphertext2 = cipher.Encrypt(block2);

        Assert.False(ciphertext1.SequenceEqual(ciphertext2));
    }

    [Fact]
    public void SetKey_ShouldThrow_WhenKeyLengthIsIncorrect()
    {
        var cipher = new RC5Cipher(32, 12, 16);

        Assert.Throws<ArgumentException>(
            () => cipher.SetKey(new byte[15]));
    }

    [Fact]
    public void Encrypt_ShouldThrow_WhenBlockLengthIsIncorrect()
    {
        var cipher = new RC5Cipher(32, 12, 16);
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentException>(
            () => cipher.Encrypt(new byte[7]));
    }

    [Fact]
    public void Decrypt_ShouldThrow_WhenBlockLengthIsIncorrect()
    {
        var cipher = new RC5Cipher(32, 12, 16);
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentException>(
            () => cipher.Decrypt(new byte[7]));
    }

    [Fact]
    public void SetKey_ShouldThrow_WhenKeyIsNull()
    {
        var cipher = new RC5Cipher(32, 12, 16);

        Assert.Throws<ArgumentNullException>(
            () => cipher.SetKey(null!));
    }

    [Fact]
    public void Encrypt_ShouldThrow_WhenBlockIsNull()
    {
        var cipher = new RC5Cipher(32, 12, 16);
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentNullException>(
            () => cipher.Encrypt(null!));
    }

    [Fact]
    public void Decrypt_ShouldThrow_WhenBlockIsNull()
    {
        var cipher = new RC5Cipher(32, 12, 16);
        cipher.SetKey(new byte[16]);

        Assert.Throws<ArgumentNullException>(
            () => cipher.Decrypt(null!));
    }

    [Fact]
    public void Encrypt_ShouldThrow_WhenKeyIsNotSet()
    {
        var cipher = new RC5Cipher(32, 12, 16);

        Assert.Throws<InvalidOperationException>(
            () => cipher.Encrypt(new byte[8]));
    }

    [Fact]
    public void Decrypt_ShouldThrow_WhenKeyIsNotSet()
    {
        var cipher = new RC5Cipher(32, 12, 16);

        Assert.Throws<InvalidOperationException>(
            () => cipher.Decrypt(new byte[8]));
    }
}
