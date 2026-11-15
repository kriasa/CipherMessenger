using src.Crypto.Symmetric.Abstractions;

namespace src.Crypto.Symmetric.Algorithms.RC5;
public sealed class RC5KeyExpansion : IKeyExpansion<ulong[]>
{
    private const ulong ShiftL = 8;
    private const ulong ShiftMixKey = 3;
    private readonly RC5Parameters _params;
    public RC5KeyExpansion(RC5Parameters parameters) 
        => _params = parameters ?? throw new ArgumentNullException(nameof(parameters));
    public ulong[] GenerateRoundKeys(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != _params.B) throw new ArgumentException("incorrect key length");

        var c = Math.Max(1, (_params.B + _params.U - 1) / _params.U);
        var t = 2 * (_params.R + 1);
        var L = InitializeL(key, c);
        var S = InitializeS(t);
        MixKey(S, L, c, t);
        return S;
    }
    private ulong[] InitializeL(byte[] key, int c)
    {
        var L = new ulong[c];
        for (int i = _params.B - 1; i >= 0; --i)
        {
            var shift = RC5Math.RotateLeft(L[i / _params.U], ShiftL, _params.W, _params.Mask);
            L[i / _params.U] = RC5Math.Add(shift, key[i], _params.Mask);
        }
        return L;
    }
    private ulong[] InitializeS(int t)
    {
        var S = new ulong[t];
        var (P, Q) = GetConstants(_params.W);
        S[0] = P;
        for (int i = 1; i < t; ++i)
        {
            S[i] = RC5Math.Add(S[i - 1], Q, _params.Mask);
        }
        return S;
    }
    private void MixKey(ulong[] S, ulong[] L, int c, int t)
    {
        var (i, j) = (0, 0);
        var (A, B) = (0UL, 0UL);
        var mask = _params.Mask;

        for (int k = 0; k < 3 * Math.Max(t, c); ++k)
        {
            A = S[i] = RC5Math.RotateLeft(RC5Math.Add(RC5Math.Add(A, B, mask), S[i], mask), ShiftMixKey, _params.W, mask);
            var sum = RC5Math.Add(A, B, mask) % (ulong)_params.W;
            B = L[j] = RC5Math.RotateLeft(RC5Math.Add(RC5Math.Add(A, B, mask), L[j], mask), sum , _params.W, mask);
            i = (i + 1) % t;
            j = (j + 1) % c;
        }
    }
    private static (ulong P, ulong Q) GetConstants(int w)=> w switch
    {
        RC5Parameters.WordSize16 => (0xB7E1UL, 0x9E37UL),
        RC5Parameters.WordSize32 => (0xB7E15163UL, 0x9E3779B9UL),
        RC5Parameters.WordSize64 => (0xB7E151628AED2A6BUL, 0x9E3779B97F4A7C15UL),
        _ => throw new ArgumentOutOfRangeException(nameof(w))
    };
}