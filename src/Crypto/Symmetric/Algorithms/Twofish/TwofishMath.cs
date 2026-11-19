namespace src.Crypto.Symmetric.Algorithms.Twofish;

public static class TwofishMath
{
    private const byte MaskGF = 0x80;
    public static byte Add(byte a, byte b) => (byte)(a ^ b);
    public static byte Multiply(byte a, byte b, byte module)
    {
        byte res = 0;
        if (a == 0 || b == 0) return res;

        while (b > 0)
        {
            if ((b & 1) == 1) res ^= a;
            a = (byte)(((a & MaskGF) != 0) ? ((a << 1) ^ module) : a << 1);
            b >>= 1;
        }
        return res;
    }
    public static byte[]  MultiplyMatrix(byte[,] matrix, ReadOnlySpan<byte> x, byte module)
    {
        var rows = matrix.GetLength(0);
        var columns = matrix.GetLength(1);
        
        if (x.Length != columns) 
            throw new ArgumentException("Vector length must match matrix columns");

        var result = new byte[rows];

        for (int i = 0; i < rows; ++i)
        {
            for (int j = 0; j < columns; ++j)
            {
                result [i] = Add(result[i], Multiply(matrix[i,j], x[j], module));
            }
        }
        return result;
    }
    public static uint MultiplyMdsColumn(byte value, int column)
    {
        uint result = 0;
        for (int row = 0; row < 4; ++row)
        {
            var product = Multiply(TwofishConstants.MDS[row, column], value, TwofishConstants.MDSPoly);
            result |= (uint)product << (8 * row);
        }
        return result;
    }
    public static uint PackageLE(byte[] value, int offset)
    {
        uint result = 0;
        for (int j = 0; j < 4; ++j)
        {
            result |= (uint)value[offset + j] << (8 * j);
        }
        return result;
    }
    public static void UnpackageLE(byte[] block, uint value, int offset)
    {
        for (int i = 0; i < 4; ++i)
        {
            block[offset + i] = (byte)(value >> (8 * i));
        }
    }
    public static byte Rol4(byte value, int shift) => (byte)(((value << shift) | (value >> (4 - shift))) & 0xF);
    public static byte Ror4(byte value, int shift) => (byte)(((value >> shift) | (value << (4 - shift))) & 0xF);
    public static uint Rol32(uint value, int shift) => (value << shift) | (value >> (32 - shift));
    public static uint Ror32(uint value, int shift) => (value >> shift) | (value << (32 - shift));
}