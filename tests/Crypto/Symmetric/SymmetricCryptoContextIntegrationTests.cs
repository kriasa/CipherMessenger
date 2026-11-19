using src.Crypto.Symmetric;
using src.Crypto.Symmetric.Algorithms.RC5;
using src.Crypto.Symmetric.Algorithms.Twofish;
using src.Crypto.Symmetric.Abstractions;
using Xunit;

namespace CipherMessenger.Tests.Crypto.Symmetric;

public sealed class SymmetricCryptoContextIntegrationTests
{
    private const int TargetChunkSize = 1024 * 1024;

    public static IEnumerable<object[]> AllModePaddingPairs =>
        from mode in Enum.GetValues<CipherMode>()
        from padding in Enum.GetValues<PaddingMode>()
        select new object[] { mode, padding };

    public static IEnumerable<object[]> AllModes =>
        Enum.GetValues<CipherMode>()
            .Select(mode => new object[] { mode });

    [Theory]
    [MemberData(nameof(AllModePaddingPairs))]
    public void RC5_ShouldWorkWithFiles(
        CipherMode mode,
        PaddingMode padding)
    {
        AssertFileRoundTrip(
            () => new RC5Cipher(32, 12, 16),
            blockSize: 8,
            mode,
            padding);
    }

    [Theory]
    [MemberData(nameof(AllModePaddingPairs))]
    public void Twofish_ShouldWorkWithFiles(
        CipherMode mode,
        PaddingMode padding)
    {
        AssertFileRoundTrip(
            () => new TwofishCipher(),
            blockSize: 16,
            mode,
            padding);
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public async Task RC5_ShouldPreserveStateAcrossFileChunks(
        CipherMode mode)
    {
        await AssertChunkBoundaryRoundTrip(
            () => new RC5Cipher(32, 12, 16),
            blockSize: 8,
            mode);
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public async Task Twofish_ShouldPreserveStateAcrossFileChunks(
        CipherMode mode)
    {
        await AssertChunkBoundaryRoundTrip(
            () => new TwofishCipher(),
            blockSize: 16,
            mode);
    }

    private static void AssertFileRoundTrip<TCipher>(
        Func<TCipher> cipherFactory,
        int blockSize,
        CipherMode mode,
        PaddingMode padding)
        where TCipher : ISymmetricCipher
    {
        int[] lengths =
        {
            0,
            1,
            blockSize - 1,
            blockSize,
            blockSize + 1
        };

        string directory = CreateTempDirectory();

        try
        {
            foreach (int length in lengths)
            {
                string inputPath = Path.Combine(directory, $"input_{length}.bin");
                string encryptedPath = Path.Combine(directory, $"encrypted_{length}.bin");
                string decryptedPath = Path.Combine(directory, $"decrypted_{length}.bin");

                byte[] original = CreateData(length);
                File.WriteAllBytes(inputPath, original);

                CreateContext(cipherFactory, blockSize, mode, padding)
                    .EncryptFile(inputPath, encryptedPath);

                CreateContext(cipherFactory, blockSize, mode, padding)
                    .DecryptFile(encryptedPath, decryptedPath);

                byte[] decrypted = File.ReadAllBytes(decryptedPath);

                Assert.Equal(original, decrypted);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task AssertChunkBoundaryRoundTrip<TCipher>(
        Func<TCipher> cipherFactory,
        int blockSize,
        CipherMode mode)
        where TCipher : ISymmetricCipher
    {
        // Проверяем переход через границу чанка.
        // Набивка влияет только на последний чанк,
        // поэтому для этой проверки достаточно одного варианта.
        int chunkSize = TargetChunkSize / blockSize * blockSize;
        int length = chunkSize + blockSize;

        string directory = CreateTempDirectory();

        try
        {
            string inputPath = Path.Combine(directory, "input.bin");
            string encryptedPath = Path.Combine(directory, "encrypted.bin");
            string decryptedPath = Path.Combine(directory, "decrypted.bin");

            byte[] original = CreateData(length);
            File.WriteAllBytes(inputPath, original);

            CreateContext(cipherFactory, blockSize, mode, PaddingMode.Pkcs)
                .EncryptFileAsync(inputPath, encryptedPath)
                .GetAwaiter()
                .GetResult();

            await CreateContext(cipherFactory, blockSize, mode, PaddingMode.Pkcs)
                .DecryptFileAsync(encryptedPath, decryptedPath);

            byte[] decrypted = await File.ReadAllBytesAsync(decryptedPath);

            Assert.Equal(original, decrypted);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static SymmetricCryptoContext<TCipher> CreateContext<TCipher>(
        Func<TCipher> cipherFactory,
        int blockSize,
        CipherMode mode,
        PaddingMode padding)
        where TCipher : ISymmetricCipher
    {
        byte[] key = new byte[16];
        byte[] iv = Enumerable.Repeat((byte)1, blockSize).ToArray();

        return new SymmetricCryptoContext<TCipher>(
            cipherFactory,
            key,
            mode,
            padding,
            iv);
    }

    private static byte[] CreateData(int length)
    {
        return Enumerable.Range(0, length)
            .Select(i => (byte)(i % 251 + 1))
            .ToArray();
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"CipherMessengerTests_{Guid.NewGuid():N}");

        Directory.CreateDirectory(path);
        return path;
    }
}
