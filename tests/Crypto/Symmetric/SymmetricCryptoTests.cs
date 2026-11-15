using Xunit;
using src.Crypto.Symmetric.Abstractions;
using src.Crypto.Symmetric.Algorithms.RC5;
using src.Crypto.Symmetric.Modes;
using src.Crypto.Symmetric.Padding;

namespace CipherMessenger.Tests.Crypto.Symmetric;

public sealed class SymmetricCryptoTests
{
    private readonly ISymmetricCipher _cipher;
    private readonly byte[] _testKey = new byte[16];
    private readonly byte[] _testIv = new byte[8];

    public SymmetricCryptoTests()
    {
        _cipher = new RC5Cipher(32, 12, 16);
        _cipher.SetKey(_testKey);
        for (int i = 0; i < _testIv.Length; i++) _testIv[i] = (byte)(i + 1);
        _testIv[^1] |= 0x01;
    }

    [Theory]
    [InlineData(typeof(PkcsPadding))]
    [InlineData(typeof(AnsiXPadding))]
    [InlineData(typeof(IsoPadding))]
    // [InlineData(typeof(ZerosPadding))]
    public void Padding_ShouldPadAndUnpadCorrectly(Type paddingType)
    {
        var padding = (IPaddingStrategy)Activator.CreateInstance(paddingType)!;
        var originalData = "Hello, Crypto World!"u8.ToArray();
        int blockSize = _cipher.BlockSize;

        var padded = padding.Pad(originalData, blockSize);

        Assert.Equal(0, padded.Length % blockSize);

        var unpadded = padding.Unpad(padded, blockSize);

        Assert.Equal(originalData, unpadded);
    }

    [Fact]
    public void ZerosPadding_ShouldPadCorrectly()
    {
        var padding = new ZerosPadding();
        var originalData = new byte[] { 0x01, 0x02, 0x03 };
        int blockSize = 8;

        var padded = padding.Pad(originalData, blockSize);

        Assert.Equal(8, padded.Length);
        Assert.Equal(0x01, padded[0]);
        Assert.Equal(0x00, padded[3]);
    }

    [Theory]
    [InlineData(typeof(EcbMode))]
    [InlineData(typeof(CbcMode))]
    [InlineData(typeof(PcbcMode))]
    [InlineData(typeof(CfbMode))]
    [InlineData(typeof(OfbMode))]
    [InlineData(typeof(CtrMode))]
    [InlineData(typeof(RandomDeltaMode))]
    public void Modes_ShouldEncryptAndDecryptCorrectly(Type modeType)
    {
        var mode = (ICipherModeStrategy)Activator.CreateInstance(modeType)!;

        var originalData = new byte[24];
        for (int i = 0; i < originalData.Length; i++) originalData[i] = (byte)(i * 13);

        object[] extraParams = Array.Empty<object>();

        var ciphertext = mode.Encrypt(originalData, _cipher, _testIv, extraParams);
        Assert.NotEqual(originalData, ciphertext);
        Assert.Equal(originalData.Length, ciphertext.Length);

        var decrypted = mode.Decrypt(ciphertext, _cipher, _testIv, extraParams);
        Assert.Equal(originalData, decrypted);
    }
}