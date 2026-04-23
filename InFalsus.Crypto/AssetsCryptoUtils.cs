namespace InFalsus.Crypto;

public class AssetsCryptoUtils
{

    public static byte[] DecryptFile(byte[] data, string fileName,
        int declaredLength)
    {
        return AssetsCrypto.DecryptLowiro(data, AssetsKeyUtils.CalcFileKeys(fileName), declaredLength);
    }
    
    public static byte[] DecryptFile(byte[] data, string fileName)
    {
        return AssetsCrypto.DecryptLowiro(data, AssetsKeyUtils.CalcFileKeys(fileName));
    }
    
}