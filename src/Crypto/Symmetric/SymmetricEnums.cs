namespace src.Crypto.Symmetric;

public enum SymmetricAlgorithmType
{
    RC5,
    Twofish
}
public enum PaddingMode
{
    Zeros,
    AnsiX,
    Pkcs,
    Iso
}
public enum CipherMode
{
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RandomDelta
}