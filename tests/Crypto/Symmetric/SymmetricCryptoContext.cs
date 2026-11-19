using src.Crypto.Symmetric;
using src.Crypto.Symmetric.Abstractions;
using Xunit;

namespace CipherMessenger.Tests.Crypto.Symmetric;

public sealed class SymmetricCryptoContextTests
{
    private static SymmetricCryptoContext<TestCipher> CreateContext(
        byte[]? iv = null)
    {
        return new SymmetricCryptoContext<TestCipher>(
            () => new TestCipher(),
            new byte[] { 1, 2, 3, 4 },
            CipherMode.ECB,
            PaddingMode.Pkcs,
            iv);
    }

    [Fact]
    public void Constructor_ShouldCreateContext()
    {
        var context = CreateContext();

        Assert.NotNull(context);
    }

    [Fact]
    public void Constructor_ShouldThrowWhenKeyIsNull()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCryptoContext<TestCipher>(
                () => new TestCipher(),
                null!,
                CipherMode.ECB,
                PaddingMode.Pkcs));
    }

    [Fact]
    public void Constructor_ShouldThrowWhenFactoryIsNull()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCryptoContext<TestCipher>(
                null!,
                new byte[] { 1, 2, 3, 4 },
                CipherMode.ECB,
                PaddingMode.Pkcs));
    }

    [Fact]
    public void Constructor_ShouldThrowWhenIvIsMissingForCbc()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCryptoContext<TestCipher>(
                () => new TestCipher(),
                new byte[] { 1, 2, 3, 4 },
                CipherMode.CBC,
                PaddingMode.Pkcs));
    }

    [Fact]
    public void Constructor_ShouldThrowWhenIvHasWrongLength()
    {
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext<TestCipher>(
                () => new TestCipher(),
                new byte[] { 1, 2, 3, 4 },
                CipherMode.CBC,
                PaddingMode.Pkcs,
                new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Constructor_ShouldAllowMissingIvForEcb()
    {
        var context = CreateContext();

        Assert.NotNull(context);
    }

    [Fact]
    public void Encrypt_ShouldThrowWhenDataIsNull()
    {
        var context = CreateContext();

        Assert.Throws<ArgumentNullException>(() =>
            context.Encrypt(null!, out _));
    }

    [Fact]
    public void Decrypt_ShouldThrowWhenDataIsNull()
    {
        var context = CreateContext();

        Assert.Throws<ArgumentNullException>(() =>
            context.Decrypt(null!, out _));
    }

    private sealed class TestCipher : ISymmetricCipher
    {
        public int BlockSize => 16;

        public void SetKey(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);
        }

        public byte[] Encrypt(byte[] block) => block.ToArray();

        public byte[] Decrypt(byte[] block) => block.ToArray();
    }
}
