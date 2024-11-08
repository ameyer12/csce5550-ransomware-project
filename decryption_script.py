import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Function to decrypt an inputted file
def decrypt_file(input_file):
    # Load the RSA private key
    with open('/Path/to/private.pem', 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Load the encrypted AES key and nonce
    with open(input_file.replace('.enc', '.key'), 'rb') as key_file:
        encrypted_aes_key = key_file.read(256)  # RSA-encrypted AES key (256 bytes for 2048-bit RSA key)
        nonce = key_file.read(8)                # Nonce (8 bytes)

    # Decrypt the AES key using RSA private key
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt the file
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    cipher_aes = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)

     # Remove '.enc' from the filename
    decrypted_file_path = input_file.replace('.enc', '')

    # Write decrypted data to file
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    print(f"File '{input_file}' has been decrypted and saved as '{decrypted_file_path}'.")

    # Remove the encrypted file after decryption
    os.remove(input_file)

    # Remove the key file after decryption
    os.remove(input_file.replace('.enc', '.key'))

# Recursively decrypt files in a directory
def decrypt_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.enc'):  # Only decrypt encrypted files
                file_path = os.path.join(root, file)
                decrypt_file(file_path)

decrypt_directory('/path/to/critical/directory')
