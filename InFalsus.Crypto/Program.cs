using System.CommandLine;

namespace InFalsus.Crypto;

public static class Program
{
    public static void Main(String[] args)
    {
        var command = new RootCommand("Crypto Tools for In Falsus")
        {
            new Argument<string>("input")
            {
                Description = "Input file path"
            },
            new Argument<string>("output")
            {
                Description = "Output file path",
            },
            new Option<string>("--mode")
            {
                Description =
                    "Crypto Mode (encrypt/decrypt).",
                DefaultValueFactory = _ => "decrypt",
                Validators =
                {
                    result =>
                    {
                        var value = result.GetValueOrDefault<string>()
                            .ToLower();
                        if (value != "decrypt" && value != "encrypt")
                        {
                            result.AddError(
                                "Mode must be one of 'decrypt', 'encrypt'");
                        }
                    }
                }
            },
            new Option<int>("--length")
            {
                Description =
                    "Length recorded in StreamingAssetsMapping for decryption.",
                DefaultValueFactory = _ => 0
            },
        };

        command.SetAction(result =>
        {
            var mode = result.GetRequiredValue<string>("mode").ToLower();
            var isDecrypt = mode == "decrypt";
            var length = result.GetValue<int>("length");
            var inputBytes =
                File.ReadAllBytes(result.GetRequiredValue<string>("input"));
            byte[] outputBytes;
            if (isDecrypt)
            {
                outputBytes = length <= 0
                    ? AssetsCrypto.DecryptLowiro(inputBytes)
                    : AssetsCrypto.DecryptLowiro(inputBytes, length);
            }
            else
            {
                outputBytes = AssetsCrypto.EncryptLowiro(inputBytes);
            }

            var outputPath = result.GetRequiredValue<string>("output");
            var parentPath = Path.GetDirectoryName(outputPath);
            if (parentPath != null)
                Directory.CreateDirectory(parentPath);
            File.WriteAllBytes(outputPath, outputBytes);
        });

        command.Parse(args).Invoke();
    }

    private static void BenchmarkDecrypt(byte[] data)
    {
        var st = DateTime.Now;
        var times = 500;
        for (int i = 0; i < times; i++)
        {
            AssetsCrypto.DecryptLowiro(data);
        }

        var timeUsedMs = (DateTime.Now - st).TotalMilliseconds;
        Console.WriteLine("=== Decryption Test Result ===");
        Console.WriteLine("File Size: " + data.Length + " byte(s)");
        Console.WriteLine("Average Time: " + timeUsedMs / times + " ms");
        var throughput =
            data.LongLength * times / (timeUsedMs / 1000) / 1024 / 1024;
        Console.WriteLine("Average Throughput: " + throughput + " MB/s");
    }
}
