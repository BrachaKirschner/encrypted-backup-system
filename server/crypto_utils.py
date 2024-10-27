import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

def generate_aes_key():
    """
    The function generates a random AES key
    :return: The generated AES key
    """
    return get_random_bytes(32) # Creating an AES-CBC key of length 256 bit

def encrypt_with_rsa(rsa_key, data):
    """
    The function encrypts the data using the RSA public key
    :param rsa_key: The RSA public key
    :param data: The data to encrypt
    :return: The encrypted data
    """
    rsa = RSA.import_key(rsa_key) # Import the client's RSA public key
    cipher_rsa = PKCS1_OAEP.new(rsa) # Create a cipher using the RSA public key
    encrypted_aes_key = cipher_rsa.encrypt(data)
    return encrypted_aes_key

def decrypt_file_with_aes(encrypted_file_path, decrypted_file_path, aes_key):
    """
    The function decrypts the file using the AES key and writes the decrypted data to a new file
    :param encrypted_file_path: The path to the encrypted file
    :param decrypted_file_path: The path to the decrypted file to write
    :param aes_key: The AES key to decrypt the file
    """

    if os.path.exists(decrypted_file_path):
        os.remove(decrypted_file_path)

    with open(decrypted_file_path, 'wb') as decrypted_file, open(encrypted_file_path, 'rb') as encrypted_file:
        buffer = encrypted_file.read()
        cipher = AES.new(aes_key, AES.MODE_CBC, b'\x00' * AES.block_size)
        decrypted_data = cipher.decrypt(buffer)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        decrypted_file.write(unpadded_data)