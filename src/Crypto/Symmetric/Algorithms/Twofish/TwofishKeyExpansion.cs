using src.Crypto.Symmetric.Abstractions;

namespace src.Crypto.Symmetric.Algorithms.Twofish;

public sealed class TwofishKeyExpansion : IKeyExpansion<(uint[] K, uint[][] S)>
{
    /// <summary>p = 2^24 + 2^16 + 2^8 + 2^1.</summary>
    private const uint P = 0x01010101u;
    private const int TotalRoundKeyPairs = TwofishConstants.Rounds + 4;
    private int _k;
    public (uint[] K, uint[][] S) GenerateRoundKeys(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!TwofishConstants.AllowedKeySizes.Contains(key.Length)) key = BuildKey(key);

        _k = key.Length / 8;
        var (S, Me, Mo) = GetBoxes(key);

        var K = new uint[2 * (TotalRoundKeyPairs)];
        for (int i = 0; i < TotalRoundKeyPairs; ++i)
        {
            var idx = (uint)i;

            uint Ai = TwofishTransformations.H(2U *idx * P, Me);
            var paramB = TwofishTransformations.H((2U * idx + 1) * P, Mo);
            uint Bi = TwofishMath.Rol32(paramB,8);
            var(a, b) = TwofishTransformations.PHT(Ai, Bi);
            (K[2* i], K[2 * i + 1]) = (a, TwofishMath.Rol32(b, 9));
        }
        return (K, S);
    }
    private (uint[][] S, uint[][] Me, uint[][] Mo) GetBoxes(byte[] key)
    {
        var (Me, Mo, S) = KeySchedule(key);
        var sBoxMe = TwofishTransformations.SBoxTransforms(Me, _k);
        var sBoxMo = TwofishTransformations.SBoxTransforms(Mo, _k);
        var sBoxS = TwofishTransformations.SBoxTransforms(S, _k);
        return (sBoxS, sBoxMe, sBoxMo);
    }
    private (uint[] Me, uint[] Mo, uint[] S) KeySchedule(byte[] key)
    {
        var Me = new uint[_k];
        var Mo = new uint[_k];

        for (int i = 0; i < _k; ++i)
        {
            Me[i] = TwofishMath.PackageLE(key, 4 * (2 * i));
            Mo[i] = TwofishMath.PackageLE(key, 4 * (2 * i + 1));
        }

        var S = new uint[_k];
        for (int i = 0; i < _k; ++i)
        {
            ReadOnlySpan<byte> m = key.AsSpan(8 * i, 8);
            var s = TwofishMath.MultiplyMatrix(TwofishConstants.RS, m, TwofishConstants.RSPoly);
            S[_k - i - 1] = TwofishMath.PackageLE(s, 0);
        }

        return (Me, Mo, S);
    }
    private static byte[] BuildKey(byte[] key)
    {
        var targetSize = key.Length switch
        {
            < TwofishConstants.KeySize128 => TwofishConstants.KeySize128,
            < TwofishConstants.KeySize192 => TwofishConstants.KeySize192,
            _ => TwofishConstants.KeySize256
        };
        var paddedKey = new byte[targetSize];
        key.CopyTo(paddedKey);
        return paddedKey;
    }
}
