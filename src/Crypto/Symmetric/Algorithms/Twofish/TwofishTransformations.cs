namespace src.Crypto.Symmetric.Algorithms.Twofish;

public static class TwofishTransformations
{
    public static uint G (uint X, uint[][] box) => H(X, box);
    public static uint H(uint X, uint[][] box)
    {
        return box[0][(byte)X] ^ box[1][(byte)(X >> 8)] ^ box[2][(byte)(X >> 16)] ^ box[3][(byte)(X >> 24)];
    }
    public static uint[][] SBoxTransforms(uint[] box, int k)
    {
        var order = TwofishConstants.GetOrderQ(k);
        var SBoxes = new uint[4][];

        for (int i = 0; i < 4; ++i)
        {
            SBoxes[i] = new uint[256];
            for (int x = 0; x < 256; ++x)
            {
                var currentX = (byte)x;
                for (int j = 0; j < k; ++j)
                {
                    var t = order[i][j] == 1 ? TwofishConstants.Q1Tables : TwofishConstants.Q0Tables;
                    var y = QPermut(t, currentX);
                    currentX = (byte)(y ^ (box[j] >> (i * 8)));
                }
                var finalTable = order[i][k] == 1 ? TwofishConstants.Q1Tables : TwofishConstants.Q0Tables;
                currentX = QPermut(finalTable, currentX);

                SBoxes[i][x] = TwofishMath.MultiplyMdsColumn(currentX, i);
            }
        }
        return SBoxes;
    }
    public static (uint aNew, uint bNew) PHT(uint a, uint b) => (a + b, a + 2 * b);
    public static byte QPermut(byte[][] t,  byte x)
    {
        var (a0, b0) = ((x >> 4) & 0xF, x & 0xF);
        var a1 = a0 ^ b0;
        var b1 = (a0 ^ TwofishMath.Ror4((byte)b0, 1) ^ 8 * a0) & 15;
        var (a2, b2) = (t[0][a1], t[1][b1]);
        var a3 = a2 ^ b2;
        var b3 = (a2 ^ TwofishMath.Ror4(b2, 1) ^ 8 * a2) & 15;
        var (a4, b4) = (t[2][a3], t[3][b3]);

        return (byte)((b4 << 4) | a4);
    }
}