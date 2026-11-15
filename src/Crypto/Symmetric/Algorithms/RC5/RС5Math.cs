namespace src.Crypto.Symmetric.Algorithms.RC5;

public static class RC5Math
{
    public static ulong Add(ulong a, ulong b, ulong mask) => (a + b) & mask;
    public static ulong Subtract(ulong a, ulong b, ulong mask) => (a - b) & mask;
    public static ulong RotateLeft(ulong value, ulong shift, int w, ulong mask)
    {
        var s = (int)(shift % (ulong)w);
        value =  value & mask;
        return ((value << s) | (value >> (w - s))) & mask;
    }
    public static ulong RotateRight(ulong value, ulong shift, int w, ulong mask)
    {
        var s = (int)(shift % (ulong)w);
        value = value & mask;
        return ((value >> s) | (value << (w - s))) & mask;
    }
}