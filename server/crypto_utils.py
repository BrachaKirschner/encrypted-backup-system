import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

CHUNK_SIZE = 1024 # 1 KB

def generate_aes_key():
    return get_random_bytes(32) # Creating an AES-CBC key of length 256 bit

def encrypt_with_rsa(rsa_key, data):
    rsa = RSA.import_key(rsa_key) # Import the client's RSA public key
    cipher_rsa = PKCS1_OAEP.new(rsa) # Create a cipher using the RSA public key
    encrypted_aes_key = cipher_rsa.encrypt(data)
    return encrypted_aes_key

def decrypt_file_with_aes(file_name, client_uuid, encrypted_file_name, aes_key):
    if not os.path.exists('backupsvr/'):
        os.makedirs('backupsvr/')
    if not os.path.exists(f'backupsvr/{client_uuid}'):
        os.makedirs(f'backupsvr/{client_uuid}')

    cipher = AES.new(aes_key, AES.MODE_CBC, b'\x00' * 16)
    with open(f'backupsvr/{client_uuid}/{file_name}', 'wb') as file, open(encrypted_file_name, 'rb') as encrypted_file:
        while chunk := encrypted_file.read(CHUNK_SIZE): # Read in chunks
            decrypted_chunk = cipher.decrypt(chunk)
            file.write(decrypted_chunk)

    # Remove padding from the last chunk
    with open(f'backupsvr/{client_uuid}/{file_name}', 'rb+') as file:
        file.seek(-CHUNK_SIZE, os.SEEK_END)
        last_chunk = file.read(CHUNK_SIZE)
        unpadded_chunk = unpad(last_chunk, AES.block_size)
        file.seek(-CHUNK_SIZE, os.SEEK_END)
        file.write(unpadded_chunk)
        file.truncate()