import struct
from request_handler import RequestHandler
from protocol import Request

class ClientSession:
    def __init__(self, client_socket):
        self.client_socket = client_socket

    def start(self):
        request = self.read_request()
        request_handler = RequestHandler(request)
        response = request_handler.handle()
        self.write_response(response)

    def read_request(self):
        # Read the fixed-size part of the request
        header_format = '!16s B H I'
        header_size = struct.calcsize(header_format)
        header_data = self.client_socket.recv(header_size)
        client_id, version, op_code, payload_size = struct.unpack(header_format, header_data)

        # Read the variable-size part of the request
        payload = self.client_socket.recv(payload_size)

        return Request(client_id, version, op_code, payload_size, payload)

    def write_response(self, response):
        response_format = f'!B H I {len(response.payload)}s'
        response_data = struct.pack(
            response_format,
            response.client_id,
            response.version,
            response.opcode,
            response.payload_size,
            response.payload
        )
        self.client_socket.sendall(response_data)