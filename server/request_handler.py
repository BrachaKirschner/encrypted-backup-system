import os
import struct
import uuid
from protocol import Response, Size, Offset, Code
from crypto_utils import decrypt_file_with_aes, encrypt_with_rsa, generate_aes_key
from cksum import compute_file_crcg


class RequestHandler:
    """ The class to handle the client requests """
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
        """ Register the user """
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
        """ Exchange the AES key """
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
        """ Login the user """
        # Extracting payload
        client_id = self.request.client_id
        # Check if the user isn't registered
        if client_id not in RequestHandler.client_data:
            self.response = Response(Code.LOGIN_FAILED.value, 0, b'')
        else:
            aes_key = generate_aes_key()
            self.client_data[client_id]['aes_key'] = aes_key # Storing the AES key in the client's data for future use
            encrypted_aes_key = encrypt_with_rsa(self.client_data[client_id]['rsa_key'], aes_key)

            # Creating the response
            payload = struct.pack(f'!{Size.CLIENT_ID_SIZE.value}s {len(encrypted_aes_key)}s', client_id, encrypted_aes_key)
            self.response = Response(Code.LOGIN_SUCCESSFUL.value, len(payload), payload)


    def backup_file(self):
        """ Backup the file """
        # Extracting payload
        message_content_size = self.request.payload_size - Offset.MESSAGE_CONTENT_OFFSET.value
        payload_format = f'!{Size.CONTENT_LENGTH_SIZE.value}s {Size.ORIGINAL_FILE_LENGTH_SIZE.value}s {Size.PACKET_NUMBER_SIZE.value}s {Size.TOTAL_PACKETS_SIZE.value}s {Size.FILE_NAME_SIZE.value}s {message_content_size}s'
        content_size, orig_file_size, packet_number, total_packets, file_name, message_content = struct.unpack(payload_format, self.request.payload)
        client_id = self.request.client_id
        client_uuid = uuid.UUID(bytes=client_id)
        aes_key = RequestHandler.client_data[client_id]['aes_key']
        file_name = file_name.rstrip(b'\x00').decode('utf-8') # Decode the file name from bytes to string and unpad it
        packet_number = int(packet_number.decode('utf-8').strip('\x00')) # Convert the packet number to an integer and unpad it
        total_packets = int(total_packets.decode('utf-8').strip('\x00')) # Convert the total packets to an integer and unpad it

        decrypted_file_path = f'backupsvr/{client_uuid}/{file_name}'
        encrypted_file_path = f'backupsvr/{client_uuid}/{file_name}.enc'

        if packet_number == 1:
            # Create the backup directories needed if it doesn't exist
            if not os.path.exists('backupsvr/'):
                os.makedirs('backupsvr/')
            if not os.path.exists(f'backupsvr/{client_uuid}'):
                os.makedirs(f'backupsvr/{client_uuid}')
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)

        # Write the message content to the encrypted temporary file
        with open(encrypted_file_path, 'ab') as file:
            file.write(message_content)

        # If this is the last packet, decrypt the encrypted file, read the CRC and file size, and send the response
        if packet_number == total_packets:
            decrypt_file_with_aes(encrypted_file_path, decrypted_file_path, aes_key)
            os.remove(encrypted_file_path) # Remove the encrypted file
            crc_str = compute_file_crc(decrypted_file_path)
            crc = int(crc_str.split('\t')[0])
            file_size = int(crc_str.split('\t')[1])

            # Creating the response
            payload_format = f'!{Size.CLIENT_ID_SIZE.value}s I {Size.FILE_NAME_SIZE.value}s I'
            payload = struct.pack(payload_format, client_id, file_size, file_name.encode('utf-8'), crc)
            self.response = Response(Code.FILE_RECEIVED.value, len(payload), payload)


    def correct_crc(self):
        """ Correct CRC received """
        self.response = Response(Code.MESSAGE_RECEIVED.value, len(self.request.client_id), self.request.client_id)

    def incorrect_crc(self):
        """ Incorrect CRC received """
        os.remove(f'backupsvr/{uuid.UUID(bytes=self.request.client_id)}/{self.request.payload.decode("utf-8")}') # Remove the backed up file with the incorrect CRC

    def fourth_incorrect_crc(self):
        """ Fourth incorrect CRC received """
        os.remove(f'backupsvr/{uuid.UUID(bytes=self.request.client_id)}/{self.request.payload.decode("utf-8")}') # Remove the backed up file with the incorrect CRC
        self.response = Response(Code.MESSAGE_RECEIVED.value, len(self.request.client_id), self.request.client_id)