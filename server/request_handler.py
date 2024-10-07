import uuid
import cryptopp
from request import Request, Size, Offset
from response import Response, Code

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
        name = self.request.payload.decode('utf-8')
        if name in RequestHandler.client_data:
            self.response = Response(1601, 0, b'')
        else:
            random_uuid = uuid.uuid4()
            RequestHandler.client_data[name] = {'uuid': random_uuid}
            self.response = Response(1600, 16, random_uuid.bytes)

    def exchange_keys(self):
        client_id = self.request.client_id # Get the client ID from the request
        rsa_key = self.request.payload[ # Extract the RSA key from the request
                  Offset.PUBLIC_KEY_OFFSET.value: Offset.PUBLIC_KEY_OFFSET.value + Size.PUBLIC_KEY_SIZE.value]
        RequestHandler.client_data[client_id]['rsa_key'] = rsa_key # Store the RSA key in the client's data
        encrypted_aes_key = generate_encrypted_aes_key(rsa_key) # Generate the encrypted AES key
        # Creating the response
        self.response = Response(Code.AES_KEY_EXCHANGE, Size.CLIENT_ID_SIZE.value + len(encrypted_aes_key), client_id.encode('utf-8') + encrypted_aes_key)

    def login_user(self):
        name = self.request.payload.decode('utf-8')
        if name not in RequestHandler.client_data:
            self.response = Response(Code.LOGIN_FAILED.value, 0, b'')
        else:
            client_id = self.request.client_id
            encrypted_aes_key = generate_encrypted_aes_key(self.client_data[client_id]['rsa_key'])
            self.response = Response(Code.LOGIN_SUCCESSFUL.value, )

    def backup_file(self):

    def correct_crc(self):

    def incorrect_crc(self):

    def fourth_incorrect_crc(self):

    def generate_encrypted_aes_key(self, rsa_key):
        # Creating an AES-CBC key of length 256 bit
        rng = cryptopp.RandomNumberGenerator()
        aes_key = rng.random_bytes(32)

        # Storing the AES key in the client's data
        client_id = self.request.client_id
        RequestHandler.client_data[client_id]['aes_key'] = aes_key

        # Encrypting the AES key using the client's RSA public key
        rsa = cryptopp.RSA(rsa_key)
        encrypted_aes_key = rsa.encrypt(aes_key)

        return encrypted_aes_key