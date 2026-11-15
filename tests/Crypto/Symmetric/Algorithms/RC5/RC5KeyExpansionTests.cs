using src.Crypto.Symmetric.Algorithms.RC5;

namespace CryptoCoursework.Tests.Algorithms.RC5;

public class RC5KeyExpansionTests
{
    [Fact]
    public void GenerateRoundKeys_ShouldReturnCorrectNumberOfKeys()
    {
        // Arrange
        var parameters = new RC5Parameters(w: 32, r: 12, b: 16);
        var expansion = new RC5KeyExpansion(parameters);
        var key = new byte[16];

        // Act
        var roundKeys = expansion.GenerateRoundKeys(key);

        // Assert
        Assert.Equal(2 * (parameters.R + 1), roundKeys.Length);
    }

    [Fact]
    public void GenerateRoundKeys_ShouldMatchKnownVector_RC5_32_12_16()
    {
        // Arrange
        var parameters = new RC5Parameters(w: 32, r: 12, b: 16);
        var expansion = new RC5KeyExpansion(parameters);
        var key = new byte[16];

        ulong[] expected =
        {
            0x9BBBD8C8,
            0x1A37F7FB,
            0x46F8E8C5,
            0x460C6085,
            0x70F83B8A,
            0x284B8303,
            0x513E1454,
            0xF621ED22
        };

        // Act
        var actual = expansion.GenerateRoundKeys(key);

        // Assert
        Assert.Equal(expected, actual.Take(expected.Length));
    }

    [Theory]
    [InlineData(16, 0xFFFFUL)]
    [InlineData(32, 0xFFFFFFFFUL)]
    [InlineData(64, 0xFFFFFFFFFFFFFFFFUL)]
    public void GenerateRoundKeys_ShouldNotExceedWordSize(int wordSize, ulong mask)
    {
        // Arrange
        var parameters = new RC5Parameters(w: wordSize, r: 12, b: 16);
        var expansion = new RC5KeyExpansion(parameters);
        var key = new byte[16];

        // Act
        var roundKeys = expansion.GenerateRoundKeys(key);

        // Assert
        Assert.All(roundKeys, roundKey =>
            Assert.Equal(roundKey & mask, roundKey));
    }

    [Fact]
    public void GenerateRoundKeys_ShouldThrow_WhenKeyLengthIsIncorrect()
    {
        // Arrange
        var parameters = new RC5Parameters(w: 32, r: 12, b: 16);
        var expansion = new RC5KeyExpansion(parameters);
        var key = new byte[15];

        // Act & Assert
        Assert.Throws<ArgumentException>(
            () => expansion.GenerateRoundKeys(key));
    }

    [Fact]
    public void GenerateRoundKeys_ShouldSupportEmptyKey()
    {
        // Arrange
        var parameters = new RC5Parameters(w: 32, r: 12, b: 0);
        var expansion = new RC5KeyExpansion(parameters);
        var key = Array.Empty<byte>();

        // Act
        var roundKeys = expansion.GenerateRoundKeys(key);

        // Assert
        Assert.Equal(26, roundKeys.Length);
    }

    [Fact]
    public void GenerateRoundKeys_ShouldProduceDifferentKeysForDifferentInputs()
    {
        // Arrange
        var parameters = new RC5Parameters(w: 32, r: 12, b: 16);
        var expansion = new RC5KeyExpansion(parameters);

        var key1 = new byte[16];
        var key2 = new byte[16];
        key2[0] = 1;

        // Act
        var roundKeys1 = expansion.GenerateRoundKeys(key1);
        var roundKeys2 = expansion.GenerateRoundKeys(key2);

        // Assert
        Assert.NotEqual(roundKeys1, roundKeys2);
    }
}