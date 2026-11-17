using System.Security.Cryptography;

namespace src.Crypto.Algorithms.Twofish;

public static class TwofishMath
{
    private const byte Mask = 0x80;
    public static byte Add(byte a, byte b) => (byte)(a ^ b);
    public static byte Multiply(byte a, byte b, byte module)
    {
        byte res = 0;
        if (a == 0 || b == 0) return res;

        while (b > 0)
        {
            if ((b & 1) == 1) res ^= a;
            a = (byte)(((a & Mask) != 0) ? ((a << 1) ^ module) : a << 1);
            b >>= 1;
        }
        return res;
    }
    public static byte[] MultiplyMatrix(byte[,] matrix, byte[] x, byte module)
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
}