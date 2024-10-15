# This file contains wrapper function for existing encryption functions of the python library pycryptodome

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AES_KEY_SIZE = 32

#generate a random AES key of size 256 bits
def generate_AES_key():
    return get_random_bytes(AES_KEY_SIZE)

# encrypt the content given the public RSA key
def RSA_encryption(content, rsa_public_key):
    if isinstance(rsa_public_key, bytes):
        public_key = RSA.import_key(rsa_public_key)  # Convert bytes to RSA key
    else:
        public_key = rsa_public_key  # If it's already an RSA key, use it directly

    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(content)

# decrypt the ciphertext given an AES key (and possible an IV)
def decrypt_aes(ciphertext, aes_key, iv=b'\x00' * 16):
    # Initialize the AES cipher in CBC mode
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)

    # Unpad the decrypted data (if padding was used during encryption)
    plaintext = unpad(decrypted_data, AES.block_size)

    return plaintext.decode('utf-8')