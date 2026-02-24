using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace InFalsus.Crypto;

public static class AssetsCrypto
{
    private static readonly byte[] DataKey = CalculateKey(612346124, 8671344);

    private static readonly byte[]
        MagicKey = CalculateKey(1611115665, 23545672);

    private static void XorVector128(Span<byte> data, Span<byte> xorValues)
    {
        int len = Math.Min(data.Length, xorValues.Length);
        int i = 0;
        for (; i + 16 <= len; i += 16)
        {
            var magicVec =
                Unsafe.ReadUnaligned<Vector128<byte>>(ref xorValues[i]);
            var dataVec = Unsafe.ReadUnaligned<Vector128<byte>>(ref data[i]);
            var result = Vector128.Xor(dataVec, magicVec);
            Unsafe.WriteUnaligned(ref data[i], result);
        }

        while (i < len)
        {
            data[i] ^= xorValues[i];
            i++;
        }
    }

    private static void XorStep(byte[] magic, byte[] data, int off, int len)
    {
        len = Math.Min(len, data.Length - off);
        XorVector128(data.AsSpan(off, len), magic);
    }

    private static void AesCryptStep(ICryptoTransform cipher,
        int inputBlockSize, byte[] data, int off, byte[] magic)
    {
        XorStep(magic, data, off, inputBlockSize);
        cipher.TransformBlock(data, off, inputBlockSize, data, off);
        XorStep(magic, data, off, inputBlockSize);
    }

    private static void CryptBlock(
        ICryptoTransform cipher,
        int inputBlockSize,
        byte[] data,
        int offset,
        int count,
        byte[] magic,
        bool toggle = true)
    {
        int blockCount = count / inputBlockSize;

        // for (int i = 0; i < blockCount - 1; i++)
        // {
        //     int off = offset + i * inputBlockSize;
        //     AesCryptStep(cipher, inputBlockSize, data, off, magic);
        //     GaloisFieldUtils.GfShift(magic);
        // }

        // Expansion of commented code above
        // Commit the AES-ECB blocks in one call for performance
        if (blockCount > 1)
        {
            int size = inputBlockSize * (blockCount - 1);
            byte[] magicBuf = new byte[size];
            for (int i = 0; i < blockCount - 1; i++)
            {
                magic.CopyTo(magicBuf, i * magic.Length);
                GaloisFieldUtils.GfShift(magic);
            }

            XorVector128(data.AsSpan(offset, size), magicBuf);
            cipher.TransformBlock(data, offset, size, data, offset);
            XorVector128(data.AsSpan(offset, size), magicBuf);
        }

        int rest = count - blockCount * inputBlockSize;
        int lastOff = offset + (blockCount - 1) * inputBlockSize;

        if (toggle && rest > 0)
        {
            int x = GaloisFieldUtils.GfShift(magic);
            AesCryptStep(cipher, inputBlockSize, data, lastOff, magic);
            GaloisFieldUtils.GfRightShift(magic, x);
        }
        else
        {
            AesCryptStep(cipher, inputBlockSize, data, lastOff, magic);
            GaloisFieldUtils.GfShift(magic);
        }

        if (rest > 0)
        {
            for (int i = 0; i < rest; i++)
            {
                int i1 = lastOff + i;
                int i2 = lastOff + inputBlockSize + i;
                (data[i1], data[i2]) = (data[i2], data[i1]);
            }

            AesCryptStep(cipher, inputBlockSize, data, lastOff, magic);
        }
    }

    private static void Crypt(byte[] data, uint magic, int dataBlockSize,
        bool isDecrypt)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = DataKey;
        var cipherData =
            isDecrypt ? aes.CreateDecryptor() : aes.CreateEncryptor();

        using var aes2 = Aes.Create();
        aes2.Mode = CipherMode.ECB;
        aes2.Padding = PaddingMode.None;
        aes2.Key = MagicKey;
        var cipherMagic = aes2.CreateEncryptor();

        int num = (data.Length - 1) / dataBlockSize + 1;
        int cnt = dataBlockSize;

        byte[] magicBytes = new byte[16];

        for (int i = 0; i < num; i++)
        {
            if (i == num - 1)
            {
                cnt = (data.Length - 1) % dataBlockSize + 1;
            }

            Array.Fill(magicBytes, (byte)0);
            BinaryPrimitives.WriteUInt64LittleEndian(magicBytes, magic);
            cipherMagic.TransformBlock(magicBytes, 0,
                16, magicBytes, 0);
            CryptBlock(cipherData, cipherData.InputBlockSize, data,
                i * dataBlockSize, cnt,
                magicBytes);
            magic++;
        }
    }

    public static void DecryptBlocks(byte[] data) => Crypt(data, 0, 512, true);

    public static void EncryptBlocks(byte[] data) =>
        Crypt(data, 0, 512, false);

    /// <summary>
    /// Recommended method for decrypting resources
    /// </summary>
    /// <param name="data">Encrypted file bytes</param>
    /// <param name="declaredLength">File length declared in StreamingAssetsMapping</param>
    /// <returns>Decrypted bytes</returns>
    public static byte[] DecryptLowiro(byte[] data, int declaredLength)
    {
        byte[] res = new byte[data.Length];
        data.CopyTo(res, 0);
        DecryptBlocks(res);

        int length = Math.Min(res.Length, declaredLength);
        if (length == res.Length)
        {
            return res;
        }

        byte[] result = new byte[length];
        res.AsSpan(0, length).CopyTo(result);
        return result;
    }

    /// <summary>
    /// Decrypt lowiro-style padded data, and try to unpad the decrypted data
    /// </summary>
    /// <param name="data">Encrypted file bytes</param>
    /// <returns>Decrypted bytes</returns>
    public static byte[] DecryptLowiro(byte[] data)
    {
        byte[] res = new byte[data.Length];
        data.CopyTo(res, 0);
        DecryptBlocks(res);

        int length = data.Length;
        if (length > 0)
        {
            int padLen = res[^1] + 1;
            if (padLen <= data.Length)
            {
                // lowiro shit padding
                bool isValidPad = true;
                for (int i = 0; i < padLen; i++)
                {
                    isValidPad &= res[res.Length - padLen + i] == i;
                }

                if (isValidPad)
                {
                    length -= padLen;
                }
            }
        }

        if (length == res.Length)
        {
            return res;
        }

        byte[] result = new byte[length];
        res.AsSpan()[..length].CopyTo(result);
        return result;
    }

    /// <summary>
    /// Encrypt the data with lowiro-style padding
    /// </summary>
    /// <param name="data">File content to be encrypted</param>
    /// <returns>Encrypted and padded data</returns>
    public static byte[] EncryptLowiro(byte[] data)
    {
        int padLen = 16 - data.Length % 16;
        byte[] res = new byte[data.Length + padLen];
        data.CopyTo(res, 0);
        // lowiro shit padding
        for (int i = 0; i < padLen; i++)
        {
            res[data.Length + i] = (byte)i;
        }

        EncryptBlocks(res);
        return res;
    }

    private static byte[] CalculateKey(int seed1, int seed2)
    {
        byte[] res = new byte[16];
        BitConverter.TryWriteBytes(res, SecretNumbers.GetSecretUlong(seed1));
        BitConverter.TryWriteBytes(res.AsSpan(8),
            SecretNumbers.GetSecretUlong(seed2));
        return res;
    }

    internal static void EncryptionTest()
    {
        byte[] data = new byte[512];
        Random.Shared.NextBytes(data);
        byte[] recovered = DecryptLowiro(EncryptLowiro(data), data.Length);
        if (!data.SequenceEqual(recovered))
        {
            throw new Exception("En/Decryption failed");
        }
    }
}