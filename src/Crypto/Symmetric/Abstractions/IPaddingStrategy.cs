namespace src.Crypto.Symmetric.Abstractions;

public interface IPaddingStrategy
{
    byte[] Pad(byte[]? data, int blockSize);
    byte[] Unpad(byte[]? data, int blockSize);
}