# Secure-File-Sharing-Tool

A simple Python-based tool for securely encrypting and decrypting files using AES encryption. This tool helps you share sensitive documents safely by protecting them with a password.

---

## Features
- **Encrypt Files**: Uses AES encryption (CBC mode) for secure file protection.
- **Decrypt Files**: Recovers the original file using the same password.
- **User-Friendly**: Easy-to-follow command-line interface.

---

## Requirements
- Python 3.6 or higher
- `cryptography` library

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/secure-file-sharing-tool.git
   cd secure-file-sharing-tool
   ```

2. Install the required Python library:
   ```bash
   pip install cryptography
   ```

---

## Usage

1. Run the script:
   ```bash
   python secure_file_sharing.py
   ```

2. Follow the prompts:
   - **Encrypt a file**:
     - Choose `(E)ncrypt`.
     - Provide the file path (e.g., `G:\Secure File Sharing Tool\example.txt`).
     - Enter a password.

     The tool will generate an encrypted file with the `.enc` extension (e.g., `example.txt.enc`).

   - **Decrypt a file**:
     - Choose `(D)ecrypt`.
     - Provide the path to the encrypted file (e.g., `example.txt.enc`).
     - Enter the same password used during encryption.

     The decrypted file will be saved with the `.dec` extension (e.g., `example.txt.dec`).

---

## Example

### Encrypting a File
```bash
Do you want to (E)ncrypt or (D)ecrypt a file? e
Enter the file path: G:\Secure File Sharing Tool\example.txt
Enter the password: ********
File encrypted and saved as G:\Secure File Sharing Tool\example.txt.enc
```

### Decrypting a File
```bash
Do you want to (E)ncrypt or (D)ecrypt a file? d
Enter the file path: G:\Secure File Sharing Tool\example.txt.enc
Enter the password: ********
File decrypted and saved as G:\Secure File Sharing Tool\example.txt.dec
```

---

## Security Notes
- Use a **strong, unique password** for encryption.
- **Share the password securely** (e.g., through a secure channel, not via email or text).
- After encryption, securely delete the original file if needed.

---

## Troubleshooting
1. **PermissionError**: Ensure the provided file path points to a file and not a directory. Verify file permissions if necessary.
2. **Invalid Password**: Ensure the password used for decryption matches the one used during encryption.

---

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for bug fixes or new features.

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

