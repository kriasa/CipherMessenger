using src.Crypto.Algorithms.Twofish;

namespace CipherMessenger.Tests.Crypto.Algorithms.Twofish;

public class TwofishTransformationsTests
{
    [Theory]
    [MemberData(nameof(GetQTables))]
    public void QPermut_ShouldBePermutation(byte[][] table)
    {
        var results = new HashSet<byte>();

        for (int value = 0; value < 256; ++value)
        {
            byte result = TwofishTransformations.QPermut(
                table,
                (byte)value);

            results.Add(result);
        }

        Assert.Equal(256, results.Count);
    }

    [Fact]
    public void QPermut_ShouldReturnExpectedValueForZero()
    {
        // Act
        byte q0 = TwofishTransformations.QPermut(
            TwofishConstants.Q0Tables, 0x00);

        byte q1 = TwofishTransformations.QPermut(
            TwofishConstants.Q1Tables, 0x00);

        // Assert
        Assert.Equal(0xA9, q0);
        Assert.Equal(0x75, q1);
    }

    [Theory]
    [InlineData(1u, 2u, 3u, 5u)]
    [InlineData(10u, 20u, 30u, 50u)]
    [InlineData(0u, 0u, 0u, 0u)]
    public void PHT_ShouldReturnExpectedValues(
        uint a,
        uint b,
        uint expectedA,
        uint expectedB)
    {
        // Act
        var result = TwofishTransformations.PHT(a, b);

        // Assert
        Assert.Equal(expectedA, result.Item1);
        Assert.Equal(expectedB, result.Item2);
    }

    [Fact]
    public void PHT_ShouldUseUnchecked32BitArithmetic()
    {
        // Arrange
        const uint a = 0xFFFFFFFF;
        const uint b = 1;

        // Act
        var result = TwofishTransformations.PHT(a, b);

        // Assert
        Assert.Equal(0u, result.Item1);
        Assert.Equal(1u, result.Item2);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void SBoxTransforms_ShouldCreateFourPermutationSBoxes(int k)
    {
        // Arrange
        uint[] keyWords =
        [
            0x03020100,
            0x07060504,
            0x0B0A0908,
            0x0F0E0D0C
        ];

        // Act
        byte[][] sBoxes = TwofishTransformations.SBoxTransforms(
            keyWords,
            k);

        // Assert
        Assert.Equal(4, sBoxes.Length);

        foreach (byte[] sBox in sBoxes)
        {
            Assert.Equal(256, sBox.Length);
            Assert.Equal(256, sBox.Distinct().Count());
        }
    }

    [Theory]
    [InlineData(0x00000000u)]
    [InlineData(0x12345678u)]
    [InlineData(0xFFFFFFFFu)]
    [InlineData(0xA1B2C3D4u)]
    public void G_ShouldMatchH(uint value)
    {
        // Arrange
        uint[] keyWords =
        [
            0x03020100,
            0x07060504,
            0x0B0A0908,
            0x0F0E0D0C
        ];

        byte[][] sBoxes = TwofishTransformations.SBoxTransforms(
            keyWords,
            4);

        // Act
        uint actual = TwofishTransformations.G(value, sBoxes);
        uint expected = TwofishTransformations.H(value, sBoxes);

        // Assert
        Assert.Equal(expected, actual);
    }

    public static IEnumerable<object[]> GetQTables =>
    [
        new object[] { TwofishConstants.Q0Tables },
        new object[] { TwofishConstants.Q1Tables }
    ];
}
