import os
import struct
import uuid
from protocol import Response, Size, Offset, Code
from crypto_utils import decrypt_file_with_aes, encrypt_with_rsa, generate_aes_key
from server.cksum import readfile


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
            self.response = Response(Code.REGISTRATION_FAILED.value, 0, b'')
        else:
            random_uuid = uuid.uuid4().bytes # Generate a random UUID of size 16 bytes
            RequestHandler.client_data[random_uuid] = {'name': name}

            # Creating the response
            payload = struct.pack(f'!{Size.CLIENT_ID_SIZE.value}s', random_uuid)
            self.response = Response(Code.REGISTRATION_SUCCESSFUL.value, len(payload), payload)


    def exchange_keys(self):
        # Extracting payload
        rsa_key = self.request.payload[ # Extract the RSA key from the request
                  Offset.PUBLIC_KEY_OFFSET.value: Offset.PUBLIC_KEY_OFFSET.value + Size.PUBLIC_KEY_SIZE.value]

        client_id = self.request.client_id
        RequestHandler.client_data[client_id]['rsa_key'] = rsa_key # Store the RSA key in the client's data for future use
        aes_key = generate_aes_key() # Generate an AES key
        RequestHandler.client_data[client_id]['aes_key'] = aes_key # Storing the AES key in the client's data for future use
        encrypted_aes_key = encrypt_with_rsa(rsa_key, aes_key) # Encrypting the AES key using the client's RSA public key

        # Creating the response
        payload = struct.pack(f'!{Size.CLIENT_ID_SIZE.value}s {len(encrypted_aes_key)}s', client_id, encrypted_aes_key)
        self.response = Response(Code.AES_KEY_EXCHANGE.value, len(payload), payload)


    def login_user(self):
        # Extracting payload
        client_id = self.request.client_id
        # Check if the user isn't registered
        if client_id not in RequestHandler.client_data:
            self.response = Response(Code.LOGIN_FAILED.value, 0, b'')
        else:
            encrypted_aes_key = self.generate_encrypted_aes_key(self.client_data[client_id]['rsa_key'])

            # Creating the response
            payload = struct.pack(f'!{Size.CLIENT_ID_SIZE.value}s {len(encrypted_aes_key)}s', client_id, encrypted_aes_key)
            self.response = Response(Code.LOGIN_SUCCESSFUL.value, len(payload), payload)


    def backup_file(self):
        # Extracting payload
        message_content_size = self.request.payload_size - Offset.MESSAGE_CONTENT_OFFSET.value
        payload_format = f'!{Size.CONTENT_LENGTH_SIZE.value}s {Size.ORIGINAL_FILE_LENGTH_SIZE.value}s {Size.PACKET_NUMBER_SIZE.value}s {Size.TOTAL_PACKETS_SIZE.value}s {Size.FILE_NAME_SIZE.value}s {message_content_size}s'
        content_size, orig_file_size, packet_number, total_packets, file_name, message_content = struct.unpack(payload_format, self.request.payload)
        file_name = file_name.rstrip(b'\x00').decode('utf-8')
        client_id = self.request.client_id
        client_uuid = uuid.UUID(bytes=client_id)
        aes_key = RequestHandler.client_data[client_id]['aes_key']

        if packet_number == 1:
            # Create a temporary file to store the packets
            if not os.path.exists(f'tmp/{client_uuid}'):
                os.makedirs(f'tmp/{client_uuid}')

        encrypted_file_name = f'tmp/{client_uuid}/{file_name}.enc'
        with open(encrypted_file_name, 'wb') as file:
            file.write(message_content)

        if packet_number == total_packets:
            decrypt_file_with_aes(file_name, client_uuid, encrypted_file_name, aes_key)
            os.remove(encrypted_file_name)

        crc_str = readfile(f'backupsvr/{client_uuid}/{file_name}')
        crc = int(crc_str.split('\t')[0])

        # Creating the response
        payload_format = f'!{Size.CLIENT_ID_SIZE.value}s, {Size.CONTENT_LENGTH_SIZE.value}s, {Size.FILE_NAME_SIZE.value}s, {Size.CHECKSUM_SIZE.value}s'
        payload = struct.pack(payload_format, client_id, len(message_content), file_name.encode('utf-8'), crc)
        self.response = Response(Code.FILE_RECEIVED.value, len(payload), payload)


    def correct_crc(self):
        self.response = Response(Code.MESSAGE_RECEIVED.value, len(self.request.client_id), self.request.client_id)

    def incorrect_crc(self):
        file_path = 'backupsvr/' + self.request.client_id + '/' + self.request.payload[Offset.FILE_NAME_OFFSET.value:].decode('utf-8')
        os.remove(file_path)

    def fourth_incorrect_crc(self):
        self.response = Response(Code.MESSAGE_RECEIVED.value, len(self.request.client_id), self.request.client_id)