# InFalsus.Crypto
AES-XTS implementation from In Falsus.

Ready to decrypt game resources.
## CLI Usage
```
Usage:
  InFalsus.Crypto <input> <output> [options]

Arguments:
  <input>   Input file path
  <output>  Output file path

Options:
  --mode <mode>      Crypto Mode (encrypt/decrypt). [default: decrypt]
  --length <length>  Length recorded in StreamingAssetsMapping for decryption. [default: 0]
  -?, -h, --help     Show help and usage information
  --version          Show version information
```
Note: File name should **exactly match** the game asset. The name is used to generate file-specific keys.  
That's input file name for decryption or output file name for encryption.
## Disclaimer
The project is for educational and research purposes only.
While the implementation is technically capable of decrypting certain structured resources (such as game assets), the authors and maintainers of this project do not endorse, encourage, or assume responsibility for any unauthorized use, reverse engineering, or circumvention of intellectual property protections.