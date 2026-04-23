using System.CommandLine;
using System.Text.RegularExpressions;

namespace InFalsus.Crypto;

public static class Program
{
    public static void Main(String[] args)
    {
        var inputArgument = new Argument<string>("input")
        {
            Description = "Input file path"
        };

        var outputArgument = new Argument<string>("output")
        {
            Description = "Output file path",
        };
        
        var modeOption = new Option<string>("--mode")
        {
            Description =
                "Crypto Mode (encrypt/decrypt).",
            DefaultValueFactory = _ => "decrypt",
            Required = false,
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
        };
        var lengthOption = new Option<int>("--length")
        {
            Description =
                "Length recorded in StreamingAssetsMapping for decryption.",
            DefaultValueFactory = _ => 0,
            Required = false
        };
        var command = new RootCommand("Crypto Tools for In Falsus")
        {
            inputArgument,
            outputArgument,
            modeOption,
            lengthOption,
        };

        command.SetAction(result =>
        {
            var mode = result.GetValue(modeOption)?.ToLower();
            var isDecrypt = mode == "decrypt";
            var length = result.GetValue(lengthOption);
            var inputPath = result.GetRequiredValue(inputArgument);
            var outputPath = result.GetRequiredValue(outputArgument);
            
            var inputBytes = File.ReadAllBytes(inputPath);
            byte[] outputBytes;
            if (isDecrypt)
            {
                var fileInfo = new FileInfo(inputPath);
                ValidateFileName(fileInfo.Name, true);
                outputBytes = length <= 0
                    ? AssetsCryptoUtils.DecryptFile(inputBytes, fileInfo.Name)
                    : AssetsCryptoUtils.DecryptFile(inputBytes, fileInfo.Name, length);
            }
            else
            {
                var fileInfo = new FileInfo(outputPath);
                ValidateFileName(fileInfo.Name, false);
                outputBytes = AssetsCryptoUtils.DecryptFile(inputBytes, fileInfo.Name);
            }

            var parentPath = Path.GetDirectoryName(outputPath);
            if (parentPath is { Length: > 0 })
                Directory.CreateDirectory(parentPath);
            File.WriteAllBytes(outputPath, outputBytes);
        });

        command.Parse(args).Invoke();
    }

    private static void ValidateFileName(string name, bool isInput)
    {
        if (!name.All(char.IsAsciiHexDigitLower) || name.Length != 21)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            string target = isInput ? "input" : "output";
            Console.WriteLine($"Asset file name should be a 32 chars lower hex string, while the currently processed {target} file does not:");
            Console.WriteLine(name);
            Console.ResetColor();
        }
    }
}
