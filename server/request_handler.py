import os
import struct
import uuid
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from request import Request, Size, Offset
from response import Response, Code, Size
from cksum import memcrc

class RequestHandler:
    # Dictionary to store all registered client data
    client_data = {}

    def __init__(self, request):
        self.request = request
        self.response = None

    def handle(self):
        handler = {
            825: self.register_user,
            826: self.exchange_keys,
            827: self.login_user,
            828: self.backup_file,
            900: self.correct_crc,
            901: self.incorrect_crc,
            902: self.fourth_incorrect_crc
        }.get(self.request.opcode)

        handler()
        return self.response


    def register_user(self):
        # Extracting payload
        name = self.request.payload.decode('utf-8')

        # Check if the user is already registered
        if name in RequestHandler.client_data:
            self.response = Response(1601, 0, b'')
        else:
            random_uuid = uuid.uuid4() # Generate a random UUID of size 16 bytes
            RequestHandler.client_data[name] = {'uuid': random_uuid}

            # Creating the response
            payload = struct.pack(f'!{Size.CLIENT_ID_SIZE.value}s', random_uuid.bytes)
            self.response = Response(1600, len(payload), payload)


    def exchange_keys(self):
        # Extracting payload
        rsa_key = self.request.payload[ # Extract the RSA key from the request
                  Offset.PUBLIC_KEY_OFFSET.value: Offset.PUBLIC_KEY_OFFSET.value + Size.PUBLIC_KEY_SIZE.value]

        client_id = self.request.client_id
        RequestHandler.client_data[client_id]['rsa_key'] = rsa_key # Store the RSA key in the client's data
        encrypted_aes_key = self.generate_encrypted_aes_key(rsa_key) # Generate the encrypted AES key

        # Creating the response
        payload = struct.pack(f'!{Size.CLIENT_ID_SIZE.value}s {len(encrypted_aes_key)}s', client_id.bytes, encrypted_aes_key)
        self.response = Response(Code.AES_KEY_EXCHANGE, len(payload), payload)


    def login_user(self):
        # Extracting payload
        name = self.request.payload.decode('utf-8')

        # Check if the user isn't registered
        if name not in RequestHandler.client_data:
            self.response = Response(Code.LOGIN_FAILED.value, 0, b'')
        else:
            client_id = self.request.client_id
            encrypted_aes_key = self.generate_encrypted_aes_key(self.client_data[client_id]['rsa_key'])
            payload = client_id + encrypted_aes_key
            self.response = Response(Code.LOGIN_SUCCESSFUL.value, len(payload), payload)


    def backup_file(self):
        # Extracting payload
        payload_format = f'!{Size.CONTENT_LENGTH_SIZE.value}s {Size.ORIGINAL_FILE_LENGTH_SIZE.value}s {Size.PACKET_NUMBER_SIZE.value}s {Size.TOTAL_PACKETS_SIZE.value}s {Size.FILE_NAME_SIZE.value}s'
        content_size, orig_file_size, packet_number, total_packets, file_name, message_content = struct.unpack(payload_format, self.request.payload)
        file_name = file_name.decode('utf-8')
        message_content = self.request.payload[Offset.MESSAGE_CONTENT_OFFSET:].decode('utf-8')

        client_id = self.request.client_id
        aes_key = RequestHandler.client_data[client_id]['aes_key']

        # Decrypt the message content
        decrypted_content = AES.new(aes_key, AES.MODE_CBC, b'\x00'*16).decrypt(message_content)

        if os.path.isdir('backupsvr/' + client_id):
            os.makedirs('backupsvr/' + client_id)
        with open('backupsvr/' + client_id + '/' + file_name, 'wb') as file:
            file.write(decrypted_content)

        crc = memcrc(decrypted_content) # Calculate the CRC of the message content

        # Creating the response
        payload_format = f'!{Size.CLIENT_ID_SIZE.value}s, {Size.CONTENT_LENGTH_SIZE.value}s, {Size.FILE_NAME_SIZE.value}s, {Size.CHECKSUM_SIZE.value}s'
        payload = struct.pack(payload_format, client_id.encode('utf-8'), len(message_content), file_name.encode('utf-8'), crc)
        self.response = Response(Code.FILE_RECEIVED.value, len(payload), payload)


    def correct_crc(self):
        self.response = Response(Code.MESSAGE_RECEIVED, len(self.request.client_id), self.request.client_id)

    def incorrect_crc(self):
        file_path = 'backupsvr/' + self.request.client_id + '/' + self.request.payload[Offset.FILE_NAME_OFFSET.value:].decode('utf-8')
        os.remove(file_path)

    def fourth_incorrect_crc(self):
        self.response = Response(Code.MESSAGE_RECEIVED, len(self.request.client_id), self.request.client_id)

    def generate_encrypted_aes_key(self, rsa_key):
        # Creating an AES-CBC key of length 256 bit
        aes_key = get_random_bytes(32)

        # Storing the AES key in the client's data
        client_id = self.request.client_id
        RequestHandler.client_data[client_id]['aes_key'] = aes_key

        # Encrypting the AES key using the client's RSA public key
        rsa = RSA.import_key(rsa_key)
        cipher_rsa = PKCS1_OAEP.new(rsa)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        return encrypted_aes_key