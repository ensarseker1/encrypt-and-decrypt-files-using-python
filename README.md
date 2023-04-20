# Encrypt and Decrypt Files using Python

```
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Encrypt a file using AES-256 encryption algorithm
def encrypt_file(file_path, password):
    chunk_size = 64 * 1024 # 64 KB
    output_file = file_path + ".encrypted"
    key = hashlib.sha256(password.encode()).digest()
    iv = get_random_bytes(16)

    encryptor = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as input_file, open(output_file, 'wb') as out_file:
        out_file.write(iv)

        while True:
            chunk = input_file.read(chunk_size)

            if len(chunk) == 0:
                break

            elif len(chunk) % 16 != 0:
                chunk += b' ' * (16 - (len(chunk) % 16))

            out_file.write(encryptor.encrypt(chunk))

    os.remove(file_path)

    return output_file

# Decrypt a file using AES-256 encryption algorithm
def decrypt_file(file_path, password):
    chunk_size = 64 * 1024 # 64 KB
    output_file = file_path.replace('.encrypted', '')
    key = hashlib.sha256(password.encode()).digest()

    with open(file_path, 'rb') as input_file, open(output_file, 'wb') as out_file:
        iv = input_file.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, iv)

        while True:
            chunk = input_file.read(chunk_size)

            if len(chunk) == 0:
                break

            out_file.write(decryptor.decrypt(chunk))

    os.remove(file_path)

    return output_file

# Main function to run the program
def main():
    file_path = input("Enter the path to the file to be encrypted: ")
    password = input("Enter the password for encryption: ")

    encrypted_file = encrypt_file(file_path, password)

    print(f"The file has been encrypted and saved as {encrypted_file}")

    decrypt_option = input("Do you want to decrypt the file? (Y/N)")

    if decrypt_option.upper() == 'Y':
        decrypted_file = decrypt_file(encrypted_file, password)

        print(f"The file has been decrypted and saved as {decrypted_file}")

if __name__ == "__main__":
    main()
```

# This code uses the PyCrypto library to implement the AES-256 encryption algorithm. When encrypting a file, the code prompts the user for a password and uses it to generate a key using SHA-256 hashing algorithm. It then encrypts the file in 64 KB chunks using Cipher Block Chaining (CBC) mode, and writes the initialization vector (IV) and the encrypted data to a new file with a ".encrypted" extension. Finally, the original file is deleted for added security.

# When decrypting a file, the code prompts the user for the password, reads the IV from the beginning of the encrypted file, and then decrypts the data using the same key and CBC mode. It then writes the decrypted data to a new file with the ".encrypted" extension removed.

# Please note that this code is intended for educational purposes only and should not be used for any malicious activities. Additionally, it may not be suitable for securing sensitive or high-risk data and should be thoroughly reviewed and tested before being used in a production environment.
