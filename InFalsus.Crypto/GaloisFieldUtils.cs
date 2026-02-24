using System.Buffers.Binary;

namespace InFalsus.Crypto;

public static class GaloisFieldUtils
{
    public static int GfShift(Span<byte> data)
    {
        // int len = data.Length;
        // int b = 0;
        // for (int i = 0; i < len; i++)
        // {
        //     byte curr = data[i];
        //     int b2 = b;
        //     b = (curr >> 7) & 0x01;
        //     data[i] = (byte)(((curr << 1) & 0xFF) | b2);
        // }
        //
        // data[0] ^= (byte)(-b & 0x87);
        // return b;

        UInt128 num = BinaryPrimitives.ReadUInt128LittleEndian(data);
        byte carry = (byte)((num >> 127) & 0x01);
        num <<= 1;
        BinaryPrimitives.WriteUInt128LittleEndian(data, num);
        data[0] ^= (byte)(-carry & 0x87);
        return carry;
    }

    public static void GfRightShift(byte[] data, int flag)
    {
        data[0] ^= 0x87;

        int num = 0;
        for (int i = data.Length - 1; i >= 0; i--)
        {
            int num2 = num;
            num = data[i] & 0x01;
            data[i] >>= 1;
            data[i] |= (byte)(num2 << 7);
        }

        data[^1] |= (byte)((flag << 7) & 0x80);
    }
}