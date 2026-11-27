using System.Numerics;
using Google.Protobuf;
using Grpc.Core;
using src.Contracts;

namespace src.Server.Services;

public static class DhValidator
{
    private const int MinPrimeBits = 256;
    private const int MaxPrimeBits = 8192;
    private const int MaxRawBytes = MaxPrimeBits / 8 + 64;

    public static (byte[] P, byte[] G) ValidateParameters(RoomDhParameters? dh)
    {
        if (dh is null) throw Invalid("Не заданы параметры DH (p, g)");

        var p = Parse(dh.P, "p");
        var g = Parse(dh.G, "g");

        var bits = p.GetBitLength();
        if (bits is < MinPrimeBits or > MaxPrimeBits)
            throw Invalid($"DH: размер p должен быть от {MinPrimeBits} до {MaxPrimeBits} бит");
        if (p.IsEven) throw Invalid("DH: p должно быть нечётным");
        if (g <= BigInteger.One || g >= p - BigInteger.One) throw Invalid("DH: g должно удовлетворять 1 < g < p-1");

        return (ToBytes(p), ToBytes(g));
    }
    public static byte[] ValidatePublicValue(ByteString value, byte[] primeBytes)
    {
        var a = Parse(value, "public_value");
        var p = new BigInteger(primeBytes, isUnsigned: true, isBigEndian: true);

        if (a <= BigInteger.One || a >= p - BigInteger.One)
            throw Invalid("DH: открытое значение должно удовлетворять 1 < A < p-1");

        return ToBytes(a);
    }
    private static BigInteger Parse(ByteString bytes, string name)
    {
        if (bytes.IsEmpty) throw Invalid($"DH: не задано значение {name}");
        if (bytes.Length > MaxRawBytes) throw Invalid($"DH: значение {name} слишком длинное");
        return new BigInteger(bytes.Span, isUnsigned: true, isBigEndian: true);
    }
    private static byte[] ToBytes(BigInteger value) => value.ToByteArray(isUnsigned: true, isBigEndian: true);
    private static RpcException Invalid(string message) => new(new Status(StatusCode.InvalidArgument, message));
}
