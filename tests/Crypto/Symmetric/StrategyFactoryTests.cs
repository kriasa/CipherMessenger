using src.Crypto.Symmetric;
using src.Crypto.Symmetric.Modes;
using src.Crypto.Symmetric.Padding;
using Xunit;

namespace CipherMessenger.Tests.Crypto.Symmetric;

public sealed class StrategyFactoryTests
{
    [Theory]
    [InlineData(CipherMode.ECB, typeof(EcbMode))]
    [InlineData(CipherMode.CBC, typeof(CbcMode))]
    [InlineData(CipherMode.PCBC, typeof(PcbcMode))]
    [InlineData(CipherMode.CFB, typeof(CfbMode))]
    [InlineData(CipherMode.OFB, typeof(OfbMode))]
    [InlineData(CipherMode.CTR, typeof(CtrMode))]
    [InlineData(CipherMode.RandomDelta, typeof(RandomDeltaMode))]
    public void CreateCipherMode_ShouldReturnCorrectStrategy(
        CipherMode mode,
        Type expectedType)
    {
        var strategy = StrategyFactory.CreateCipherMode(mode);

        Assert.NotNull(strategy);
        Assert.IsType(expectedType, strategy);
    }

    [Theory]
    [InlineData(PaddingMode.Zeros, typeof(ZerosPadding))]
    [InlineData(PaddingMode.AnsiX, typeof(AnsiXPadding))]
    [InlineData(PaddingMode.Pkcs, typeof(PkcsPadding))]
    [InlineData(PaddingMode.Iso, typeof(IsoPadding))]
    public void CreatePadding_ShouldReturnCorrectStrategy(
        PaddingMode mode,
        Type expectedType)
    {
        var strategy = StrategyFactory.CreatePadding(mode);

        Assert.NotNull(strategy);
        Assert.IsType(expectedType, strategy);
    }

    [Theory]
    [InlineData(CipherMode.ECB, false)]
    [InlineData(CipherMode.CBC, true)]
    [InlineData(CipherMode.PCBC, true)]
    [InlineData(CipherMode.CFB, true)]
    [InlineData(CipherMode.OFB, true)]
    [InlineData(CipherMode.CTR, true)]
    [InlineData(CipherMode.RandomDelta, true)]
    public void RequiresIv_ShouldReturnCorrectResult(
        CipherMode mode,
        bool expected)
    {
        Assert.Equal(expected, StrategyFactory.RequiresIv(mode));
    }

    [Fact]
    public void CreateCipherMode_ShouldThrowForUnknownValue()
    {
        var invalidMode = (CipherMode)999;

        Assert.Throws<ArgumentOutOfRangeException>(
            () => StrategyFactory.CreateCipherMode(invalidMode));
    }

    [Fact]
    public void CreatePadding_ShouldThrowForUnknownValue()
    {
        var invalidMode = (PaddingMode)999;

        Assert.Throws<ArgumentOutOfRangeException>(
            () => StrategyFactory.CreatePadding(invalidMode));
    }
}
