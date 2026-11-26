using Grpc.Core;
using src.Contracts;

namespace src.Server.Services;

public static class CipherSettingsValidator
{
    private static readonly uint[] Rc5WordSizes = [16, 32, 64];
    private static readonly uint[] TwofishKeySizes = [16, 24, 32];

    public static void Validate(CipherSettings? s)
    {
        if (s is null) throw Invalid("Encryption parameters are not specified");

        if (!IsSet(s.Mode)) throw Invalid("Encryption mode not selected");
        if (!IsSet(s.Padding)) throw Invalid("Padding not selected");

        switch (s.AlgorithmParametersCase)
        {
            case CipherSettings.AlgorithmParametersOneofCase.Rc5:
                var rc5 = s.Rc5;
                if (!Rc5WordSizes.Contains(rc5.WordSizeBits)) throw Invalid("RC5: word size 16, 32 or 64 bit");
                if (rc5.Rounds is < 1 or > 255) throw Invalid("RC5: rounds [1,255]");
                if (rc5.KeySizeBytes is < 1 or > 255) throw Invalid("RC5: len key [1,255] byte");
                break;

            case CipherSettings.AlgorithmParametersOneofCase.Twofish:
                if (!TwofishKeySizes.Contains(s.Twofish.KeySizeBytes)) throw Invalid("Twofish len key 16, 24 or 32 byte");
                break;

            default:
                throw Invalid("No encryption algorithm selected: please set rc5 or twofish parameters");
        }
    }
    private static bool IsSet<T>(T value) where T : struct, Enum
        => Enum.IsDefined(value) && Convert.ToInt32(value) != 0;

    private static RpcException Invalid(string message) => new(new Status(StatusCode.InvalidArgument, message));
}
