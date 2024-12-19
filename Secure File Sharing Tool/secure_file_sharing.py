from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64
import getpass

# Generate a key from a password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file
def encrypt_file(file_path: str, password: str):
    # Generate a random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    
    # Read the file and encrypt
    with open(file_path, 'rb') as f:
        data = f.read()
    
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Save encrypted file with salt and IV
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)
    print(f"File encrypted and saved as {file_path}.enc")

# Decrypt a file
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    iv = data[16:32]
    encrypted_data = data[32:]
    
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    # Save the decrypted file
    decrypted_file_path = file_path.replace('.enc', '.dec')
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    print(f"File decrypted and saved as {decrypted_file_path}")

# Main function for user interaction
if __name__ == "__main__":
    choice = input("Do you want to (E)ncrypt or (D)ecrypt a file? ").strip().lower()
    file_path = input("Enter the file path: ").strip()
    password = getpass.getpass("Enter the password: ").strip()
    
    if choice == 'e':
        encrypt_file(file_path, password)
    elif choice == 'd':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice.")
