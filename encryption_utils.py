from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AES_KEY_SIZE = 32

def generate_AES_key():
    return get_random_bytes(AES_KEY_SIZE)

def RSA_encryption(content, rsa_public_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    return cipher_rsa.encrypt(content)


def decrypt_aes(ciphertext, aes_key, iv=b'\x00' * 16):
    # Initialize the AES cipher in CBC mode
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)

    # Unpad the decrypted data (if padding was used during encryption)
    plaintext = unpad(decrypted_data, AES.block_size)

    return plaintext.decode('utf-8')