import enum


class Response:
    def __init__(self, opcode, payload_size, payload):
        self.version = 3
        self.opcode = opcode
        self.payload_size = payload_size
        self.payload = payload

class Code(enum.Enum):
    REGISTRATION_SUCCESSFUL = 1600
    REGISTRATION_FAILED = 1601
    AES_KEY_EXCHANGE = 1602
    FILE_RECEIVED = 1603
    MESSAGE_RECEIVED = 1604
    LOGIN_SUCCESSFUL = 1605
    LOGIN_FAILED = 1606
    GENERAL_ERROR = 1607