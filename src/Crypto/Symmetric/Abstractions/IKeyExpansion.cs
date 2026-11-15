namespace src.Crypto.Symmetric.Abstractions;

public interface IKeyExpansion<TSubKeys>
{
    TSubKeys GenerateRoundKeys(byte[] key);
}