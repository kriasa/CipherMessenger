using src.Crypto.Symmetric.Modes;
using src.Crypto.Symmetric.Padding;
using src.Crypto.Symmetric.Abstractions;

namespace src.Crypto.Symmetric;

public static class StrategyFactory
{
    public static ICipherModeStrategy CreateCipherMode(CipherMode cipherMode) => cipherMode switch
    {
        CipherMode.ECB => new EcbMode(),
        CipherMode.CBC => new CbcMode(),
        CipherMode.PCBC => new PcbcMode(),
        CipherMode.CFB => new CfbMode(),
        CipherMode.OFB => new OfbMode(),
        CipherMode.CTR => new CtrMode(),
        CipherMode.RandomDelta => new RandomDeltaMode(),
        _ => throw new ArgumentOutOfRangeException(nameof(cipherMode), cipherMode, "Unknown encryption mode")
    };

    public static IPaddingStrategy CreatePadding(PaddingMode paddingMode) => paddingMode switch
    {
        PaddingMode.Zeros => new ZerosPadding(),
        PaddingMode.AnsiX => new AnsiXPadding(),
        PaddingMode.Pkcs => new PkcsPadding(),
        PaddingMode.Iso => new IsoPadding(),
        _ => throw new ArgumentOutOfRangeException(nameof(paddingMode), paddingMode, "Unknown padding mode")
    };
    public static bool RequiresIv(CipherMode cipherMode) => cipherMode != CipherMode.ECB;
}