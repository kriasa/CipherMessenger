
using Xunit;
using src.Crypto.Algorithms.Twofish;

namespace CipherMessenger.Tests.Crypto.Algorithms.Twofish;

public sealed class TwofishMathTests
{
    private const byte MDSPoly = 0x69;
    private const byte RSPoly = 0x4D;

    #region Add

    [Theory]
    [InlineData(0x57, 0x83, 0xD4)]
    [InlineData(0x00, 0x57, 0x57)]
    [InlineData(0xAA, 0xAA, 0x00)]
    [InlineData(0xFF, 0x01, 0xFE)]
    public void Add_ShouldReturnCorrectResult(
        byte a, byte b, byte expected)
    {
        var actual = TwofishMath.Add(a, b);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Add_ShouldBeCommutative()
    {
        for (int a = 0; a <= byte.MaxValue; ++a)
        {
            for (int b = 0; b <= byte.MaxValue; ++b)
            {
                Assert.Equal(
                    TwofishMath.Add((byte)a, (byte)b),
                    TwofishMath.Add((byte)b, (byte)a));
            }
        }
    }

    [Fact]
    public void Add_ShouldReturnZero_WhenAddingSameElements()
    {
        for (int a = 0; a <= byte.MaxValue; ++a)
        {
            Assert.Equal(
                0,
                TwofishMath.Add((byte)a, (byte)a));
        }
    }

    #endregion

    #region Multiply

    [Theory]
    [InlineData(0x57, 0x83, 0x69, 0x46)]
    [InlineData(0x57, 0x83, 0x4D, 0x43)]
    [InlineData(0xFF, 0xFF, 0x69, 0x90)]
    [InlineData(0xFF, 0xFF, 0x4D, 0xF6)]
    [InlineData(0x02, 0x80, 0x69, 0x69)]
    [InlineData(0x02, 0x80, 0x4D, 0x4D)]
    public void Multiply_ShouldReturnCorrectResult(
        byte a, byte b, byte module, byte expected)
    {
        var actual = TwofishMath.Multiply(a, b, module);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0x69)]
    [InlineData(0x4D)]
    public void Multiply_ByZero_ShouldReturnZero(byte module)
    {
        Assert.Equal(0, TwofishMath.Multiply(0, 0x57, module));
        Assert.Equal(0, TwofishMath.Multiply(0x57, 0, module));
    }

    [Theory]
    [InlineData(0x69)]
    [InlineData(0x4D)]
    public void Multiply_ByOne_ShouldReturnSameElement(byte module)
    {
        for (int a = 0; a <= byte.MaxValue; ++a)
        {
            Assert.Equal(
                (byte)a,
                TwofishMath.Multiply((byte)a, 1, module));
        }
    }

    [Theory]
    [InlineData(0x69)]
    [InlineData(0x4D)]
    public void Multiply_ShouldBeCommutative(byte module)
    {
        byte[] values = { 0x00, 0x01, 0x02, 0x57, 0x80, 0xA3, 0xFF };

        foreach (byte a in values)
        {
            foreach (byte b in values)
            {
                Assert.Equal(
                    TwofishMath.Multiply(a, b, module),
                    TwofishMath.Multiply(b, a, module));
            }
        }
    }

    [Theory]
    [InlineData(0x69)]
    [InlineData(0x4D)]
    public void Multiply_ShouldBeDistributive(byte module)
    {
        byte[] values = { 0x00, 0x01, 0x02, 0x57, 0x83, 0xA3, 0xFF };

        foreach (byte a in values)
        {
            foreach (byte b in values)
            {
                foreach (byte c in values)
                {
                    var left = TwofishMath.Multiply(
                        a, TwofishMath.Add(b, c), module);

                    var right = TwofishMath.Add(
                        TwofishMath.Multiply(a, b, module),
                        TwofishMath.Multiply(a, c, module));

                    Assert.Equal(left, right);
                }
            }
        }
    }

    #endregion

    #region MultiplyMatrix

    private static readonly byte[,] MDS =
    {
        { 0x01, 0xEF, 0x5B, 0x5B },
        { 0x5B, 0xEF, 0xEF, 0x01 },
        { 0xEF, 0x5B, 0x01, 0xEF },
        { 0xEF, 0x01, 0xEF, 0x5B }
    };

    private static readonly byte[,] RS =
    {
        { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E },
        { 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5 },
        { 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19 },
        { 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03 }
    };

    [Fact]
    public void MultiplyMatrix_MDS_ShouldReturnCorrectResult()
    {
        byte[] vector = { 0x01, 0x23, 0x45, 0x67 };
        byte[] expected = { 0xFF, 0xC4, 0x78, 0xC4 };

        var actual = TwofishMath.MultiplyMatrix(
            MDS, vector, MDSPoly);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MultiplyMatrix_RS_ShouldReturnCorrectResult()
    {
        byte[] vector = { 0x00, 0x01, 0x02, 0x03,
                          0x04, 0x05, 0x06, 0x07 };

        byte[] expected = { 0xD7, 0x2A, 0x06, 0x2F };

        var actual = TwofishMath.MultiplyMatrix(
            RS, vector, RSPoly);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MultiplyMatrix_MDS_ShouldReturnCorrectColumns()
    {
        byte[][] expectedColumns =
        {
            new byte[] { 0x01, 0x5B, 0xEF, 0xEF },
            new byte[] { 0xEF, 0xEF, 0x5B, 0x01 },
            new byte[] { 0x5B, 0xEF, 0x01, 0xEF },
            new byte[] { 0x5B, 0x01, 0xEF, 0x5B }
        };

        for (int j = 0; j < 4; ++j)
        {
            var vector = new byte[4];
            vector[j] = 1;

            var actual = TwofishMath.MultiplyMatrix(
                MDS, vector, MDSPoly);

            Assert.Equal(expectedColumns[j], actual);
        }
    }

    [Fact]
    public void MultiplyMatrix_RS_ShouldReturnCorrectColumns()
    {
        byte[][] expectedColumns =
        {
            new byte[] { 0x01, 0xA4, 0x02, 0xA4 },
            new byte[] { 0xA4, 0x56, 0xA1, 0x55 },
            new byte[] { 0x55, 0x82, 0xFC, 0x87 },
            new byte[] { 0x87, 0xF3, 0xC1, 0x5A },
            new byte[] { 0x5A, 0x1E, 0x47, 0x58 },
            new byte[] { 0x58, 0xC6, 0xAE, 0xDB },
            new byte[] { 0xDB, 0x68, 0x3D, 0x9E },
            new byte[] { 0x9E, 0xE5, 0x19, 0x03 }
        };

        for (int j = 0; j < 8; ++j)
        {
            var vector = new byte[8];
            vector[j] = 1;

            var actual = TwofishMath.MultiplyMatrix(
                RS, vector, RSPoly);

            Assert.Equal(expectedColumns[j], actual);
        }
    }

    [Fact]
    public void MultiplyMatrix_ZeroVector_ShouldReturnZeroVector()
    {
        var vector = new byte[4];

        var actual = TwofishMath.MultiplyMatrix(
            MDS, vector, MDSPoly);

        Assert.Equal(new byte[4], actual);
    }

    [Fact]
    public void MultiplyMatrix_ShouldThrow_WhenVectorLengthIsIncorrect()
    {
        byte[] incorrectVector = new byte[3];

        Assert.Throws<ArgumentException>(() =>
            TwofishMath.MultiplyMatrix(
                MDS, incorrectVector, MDSPoly));
    }

    #endregion
}
