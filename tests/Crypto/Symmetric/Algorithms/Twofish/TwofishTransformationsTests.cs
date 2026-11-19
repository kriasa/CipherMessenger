using src.Crypto.Symmetric.Algorithms.Twofish;

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
        byte q0 = TwofishTransformations.QPermut(
            TwofishConstants.Q0Tables, 0x00);

        byte q1 = TwofishTransformations.QPermut(
            TwofishConstants.Q1Tables, 0x00);

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
        var result = TwofishTransformations.PHT(a, b);

        Assert.Equal(expectedA, result.Item1);
        Assert.Equal(expectedB, result.Item2);
    }

    [Fact]
    public void PHT_ShouldUseUnchecked32BitArithmetic()
    {
        const uint a = 0xFFFFFFFF;
        const uint b = 1;

        var result = TwofishTransformations.PHT(a, b);

        Assert.Equal(0u, result.Item1);
        Assert.Equal(1u, result.Item2);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void SBoxTransforms_ShouldCreateFourMdsContributionTables(int k)
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
        uint[][] sBoxes = TwofishTransformations.SBoxTransforms(
            keyWords,
            k);

        // Assert
        Assert.Equal(4, sBoxes.Length);

        foreach (uint[] sBox in sBoxes)
        {
            Assert.Equal(256, sBox.Length);
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

        uint[][] sBoxes = TwofishTransformations.SBoxTransforms(
            keyWords,
            4);

        // Act
        uint actual = TwofishTransformations.G(value, sBoxes);
        uint expected = TwofishTransformations.H(value, sBoxes);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0x00000000u)]
    [InlineData(0x12345678u)]
    [InlineData(0xFFFFFFFFu)]
    [InlineData(0xA1B2C3D4u)]
    public void H_ShouldMatchDirectMdsCalculation(uint value)
    {
        // Arrange
        uint[] keyWords =
        [
            0x03020100,
            0x07060504,
            0x0B0A0908,
            0x0F0E0D0C
        ];

        const int k = 4;

        uint[][] sBoxes = TwofishTransformations.SBoxTransforms(
            keyWords,
            k);

        // Act
        uint actual = TwofishTransformations.H(value, sBoxes);
        uint expected = CalculateHDirectly(value, keyWords, k);

        // Assert
        Assert.Equal(expected, actual);
    }

    private static uint CalculateHDirectly(
        uint value,
        uint[] keyWords,
        int k)
    {
        var order = TwofishConstants.GetOrderQ(k);
        Span<byte> y = stackalloc byte[4];

        for (int i = 0; i < 4; ++i)
        {
            byte currentX = (byte)(value >> (8 * i));

            for (int j = 0; j < k; ++j)
            {
                var table = order[i][j] == 1
                    ? TwofishConstants.Q1Tables
                    : TwofishConstants.Q0Tables;

                byte transformed = TwofishTransformations.QPermut(
                    table,
                    currentX);

                currentX = (byte)(
                    transformed ^ (byte)(keyWords[j] >> (8 * i)));
            }

            var finalTable = order[i][k] == 1
                ? TwofishConstants.Q1Tables
                : TwofishConstants.Q0Tables;

            y[i] = TwofishTransformations.QPermut(
                finalTable,
                currentX);
        }

        var result = TwofishMath.MultiplyMatrix(
            TwofishConstants.MDS,
            y,
            TwofishConstants.MDSPoly);

        return TwofishMath.PackageLE(result, 0);
    }

    public static IEnumerable<object[]> GetQTables =>
    [
        new object[] { TwofishConstants.Q0Tables },
        new object[] { TwofishConstants.Q1Tables }
    ];
}
