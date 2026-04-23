using System.Security.Cryptography;
using System.Text;

namespace InFalsus.Crypto;

public class AssetsKeyUtils
{
    private static readonly int[] SecretSeeds =
    [
        612346124, 8671344, 1611115665, 23545672
    ];

    private static readonly ulong[] XorValues =
    [
        6927911050464092881UL,
        1447651736806110927UL,
        12076203419723673410UL,
        17918238998231163082UL
    ];

    public static byte[] CalcFileXorBytes(string guid)
    {
        byte[] msg1 = SecretSeeds
            .Zip(XorValues, (seed, xorVal) =>
            {
                ulong val = SecretNumbers.GetSecretUlong(seed) ^ xorVal;
                return BitConverter.GetBytes(val);
            })
            .SelectMany(b => b)
            .ToArray();

        // digest_1 = HMAC-SHA256(guid, msg1)
        byte[] key = Encoding.UTF8.GetBytes(guid);
        byte[] digest1;

        using (var hmac = new HMACSHA256(key))
        {
            digest1 = hmac.ComputeHash(msg1);
        }

        byte[] msg2 = "asset-guid\u0001"u8.ToArray();

        // HMAC-SHA256(digest1, msg2)
        using (var hmac = new HMACSHA256(digest1))
        {
            return hmac.ComputeHash(msg2);
        }
    }

    public static AssetsCrypto.AesXtsKeys CalcFileKeys(string guid)
    {
        byte[] array = XorValues
            .SelectMany(BitConverter.GetBytes)
            .ToArray();

        byte[] xorArray = CalcFileXorBytes(guid);

        byte[] xorArray2 = SecretSeeds
            .SelectMany(seed =>
                BitConverter.GetBytes(SecretNumbers.GetSecretUlong(seed)))
            .ToArray();

        byte[] result = new byte[array.Length];
        for (int i = 0; i < array.Length; i++)
        {
            result[i] = (byte)(array[i] ^ xorArray[i] ^ xorArray2[i]);
        }

        byte[] dataKey = result.Take(16).ToArray();
        byte[] tweakKey = result.Skip(16).Take(16).ToArray();

        return new AssetsCrypto.AesXtsKeys(dataKey, tweakKey);
    }
    
}