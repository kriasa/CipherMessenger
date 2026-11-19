using src.Crypto.Symmetric.Abstractions;

namespace src.Crypto.Symmetric.Algorithms.Twofish;

public sealed class TwofishCipher : ISymmetricCipher
{
    private const int SubkeysOffset = 8;
    public int BlockSize => TwofishConstants.BlockSizeByte;
    private readonly IKeyExpansion<(uint[] K, uint[][] S)> _keyExpansion;

    private uint[]? _k;
    private uint[][]? _sBox;

    public TwofishCipher() => _keyExpansion = new TwofishKeyExpansion();
    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length > TwofishConstants.KeySize256 || key.Length == 0) 
            throw new ArgumentException("Incorrect block length");
        (_k, _sBox) = _keyExpansion.GenerateRoundKeys(key);
    }
    public uint G(uint X, uint[][] box) => TwofishTransformations.G(X, box);
    public byte[] Encrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize) throw new ArgumentException("Incorrect block length");
        if (_k == null || _sBox == null) throw new InvalidOperationException("Key is not set");

        Span<uint> R = stackalloc uint[4];
        for (int i = 0; i < 4;++i)
        {
            R[i] = TwofishMath.PackageLE(block,i * 4) ^ _k[i];
        }

        for (int r = 0; r < TwofishConstants.Rounds; ++r)
        {
            var (F0, F1) = F(R[0], R[1], r);
            (F0, F1) = (F0 + _k[2 * r + SubkeysOffset], F1 + _k[2 * r + SubkeysOffset + 1]);

            (R[0], R[2]) = (TwofishMath.Ror32(R[2] ^ F0, 1), R[0]);
            (R[1], R[3]) = (TwofishMath.Rol32(R[3], 1) ^ F1, R[1]);
        }

        var result = new byte[BlockSize];
        for (int i = 0; i < 4; ++i)
        {
            TwofishMath.UnpackageLE(result, R[(i + 2) % 4] ^ _k[4 + i], 4 * i);
        }
        return result;
    }
    public byte[] Decrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize) throw new ArgumentException("Incorrect block length");
        if (_k == null || _sBox == null) throw new InvalidOperationException("Key is not set");

        Span<uint> R = stackalloc uint[4];
        for (int i = 0; i < 4; ++i)
        {
            R[(i + 2) % 4] = TwofishMath.PackageLE(block, i * 4) ^ _k[4 + i];
        }

        for (int r = TwofishConstants.Rounds - 1; r >= 0; --r)
        {
            var (F0, F1) = F(R[2], R[3], r);
            (F0, F1) = (F0 + _k[2 * r + 8], F1 + _k[2 * r + 9]);

            (R[0], R[2]) = (R[2], TwofishMath.Rol32(R[0], 1) ^ F0);
            (R[1], R[3]) = (R[3], TwofishMath.Ror32(R[1] ^ F1, 1));
        }

        var result = new byte[BlockSize];
        for (int i = 0; i < 4; ++i)
        {
            TwofishMath.UnpackageLE(result, R[i] ^ _k[i], 4 * i);
        }

        return result;
    }
    private (uint F0, uint F1) F(uint R0, uint R1, int r)
    {
        uint T0 = G(R0, _sBox);
        uint T1 = G(TwofishMath.Rol32(R1, 8), _sBox);
        (T0, T1) = TwofishTransformations.PHT(T0, T1);
        return (T0, T1);
    }
}