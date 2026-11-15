namespace src.Crypto.Symmetric.Algorithms.RC5;

public sealed class RC5Parameters
{
    public const int WordSize16 = 16;
    public const int WordSize32 = 32;
    public const int WordSize64 = 64;
    private const int BitPerByte = 8;
    private static readonly int[] AllowedWordSizes = { WordSize16, WordSize32, WordSize64 };
    public int W { get; }
    public int B { get; }
    public int R { get; }

    public int BlockSize {get;}
    public int U {get;}
    public ulong Mask {get;}

    public RC5Parameters(int w = WordSize32, int r = 12, int b = 16)
    {
        if (!AllowedWordSizes.Contains(w)) throw new ArgumentOutOfRangeException(nameof(w), "RC5: w must be 16, 32 or 64");
        if (r < 0 || r > 255) throw new ArgumentOutOfRangeException(nameof(r), "RC5: r must be in 0..255");
        if (b < 0 || b > 255) throw new ArgumentOutOfRangeException(nameof(b), "RC5: b must be in 0..255");

        W = w;
        B = b;
        R = r;
        U = w / BitPerByte;
        BlockSize = U * 2;
        Mask = (w == WordSize64) ? ulong.MaxValue : (1UL << w) - 1;
    }
}