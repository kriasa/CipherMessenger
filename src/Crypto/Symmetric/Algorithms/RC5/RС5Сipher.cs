using src.Crypto.Symmetric.Abstractions;

namespace src.Crypto.Symmetric.Algorithms.RC5;

public sealed class RC5Cipher : ISymmetricCipher
{
    private const int BitPerByte = 8;
    private readonly RC5Parameters _parameters;
    private readonly IKeyExpansion<ulong[]> _keyExpansion;
    private ulong[]? _S;
    public int BlockSize => _parameters.BlockSize;
    private ulong[] S => _S ?? throw new InvalidOperationException("key is not set");
    public RC5Cipher(RC5Parameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        _keyExpansion = new RC5KeyExpansion(_parameters);
    }
    public RC5Cipher(int w, int r, int b) : this(new RC5Parameters (w, r, b)){}
    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _S = _keyExpansion.GenerateRoundKeys(key);
    }
    public byte[] Encrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize) throw new ArgumentException("incorrect block length");

        var A = ReadWord(block, 0);
        var B = ReadWord(block, _parameters.U);
        var mask = _parameters.Mask;

        A = RC5Math.Add(A, S[0], mask);
        B = RC5Math.Add(B, S[1], mask);

        for (int i = 1; i <= _parameters.R; ++i)
        {
            A = RC5Math.Add(RC5Math.RotateLeft(A ^ B, B, _parameters.W, mask), S[2 * i], mask);
            B = RC5Math.Add(RC5Math.RotateLeft(B ^ A, A, _parameters.W, mask), S[2 * i + 1], mask);
        }

        var result = new byte[BlockSize];
        WriteWord(result, A, 0);
        WriteWord(result, B, _parameters.U);

        return result;
    }
    public byte[] Decrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSize) throw new ArgumentException("incorrect block length");

        var A = ReadWord(block, 0);
        var B = ReadWord(block, _parameters.U);
        var mask = _parameters.Mask;

        for (int i = _parameters.R; i > 0; --i)
        {
            B = RC5Math.RotateRight(RC5Math.Subtract(B, S[2 * i + 1], mask), A, _parameters.W, mask) ^ A;
            A = RC5Math.RotateRight(RC5Math.Subtract(A, S[2 * i], mask), B, _parameters.W, mask) ^ B;
        }

        B = RC5Math.Subtract(B, S[1], mask);
        A = RC5Math.Subtract(A, S[0], mask);

        var result = new byte[BlockSize];
        WriteWord(result, A, 0);
        WriteWord(result, B, _parameters.U);

        return result;
    }
    private ulong ReadWord(byte[] block, int offset)
    {
        var result = 0UL;
        for (int i = 0; i < _parameters.U; ++i)
        {
            result |= (ulong)block[offset + i] << (BitPerByte * i);
        }
        return result;
    }
    private void WriteWord(byte[] block, ulong value, int offset)
    {
        for (int i = 0; i < _parameters.U; ++i)
        {
            block[offset + i] = (byte)(value >> (BitPerByte * i));
        }
    }
}