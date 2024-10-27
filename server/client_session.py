import struct
from request_handler import RequestHandler
from protocol import Request, Code


class ClientSession:
    def __init__(self, client_socket):
        """
        Initialize the client session
        :param client_socket: The client socket
        """
        self.client_socket = client_socket

    def start(self):
        """
        Start the client session
        """
        while True:
            try:
                request = self.read_request()
                request_handler = RequestHandler(request)
                response = request_handler.handle()
                if response: # The response is None if a packet that isn't the last one is received
                    self.write_response(response)
                    if response.opcode == Code.MESSAGE_RECEIVED.value: # If the backup is successful, break the loop
                        print("File backup successful, closing connection")
                        break
            except Exception as e:
                print(f"Error: {e}")
                break

    def read_request(self):
        """
        Read the request from the client
        :return: The request
        """
        # Read the fixed-size part of the request (header)
        header_format = '!16s B H I'
        header_size = struct.calcsize(header_format)
        header_data = b''
        while len(header_data) < header_size: # Loop until all header bytes are read
            packet = self.client_socket.recv(header_size - len(header_data))
            if not packet:
                raise ConnectionError("Socket connection lost")
            header_data += packet
        client_id, version, op_code, payload_size = struct.unpack(header_format, header_data)

        # Read the variable-size part of the request (payload)
        payload = b''
        while len(payload) < payload_size:  # Loop until all payload bytes are read
            packet = self.client_socket.recv(payload_size - len(payload))
            if not packet:
                raise ConnectionError("Socket connection lost")
            payload += packet

        return Request(client_id, version, op_code, payload_size, payload)

    def write_response(self, response):
        """
        Write the response to the client
        :param response: The response
        """
        response_format = f'!B H I {len(response.payload)}s'
        response_data = struct.pack(
            response_format,
            response.version,
            response.opcode,
            response.payload_size,
            response.payload
        )
        self.client_socket.sendall(response_data)