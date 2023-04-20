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
