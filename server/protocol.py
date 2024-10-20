import enum

# Request class and related enums
class Request:
    def __init__(self, client_id, version, opcode, payload_size, payload):
        self.client_id = client_id
        self.version = version
        self.opcode = opcode
        self.payload_size = payload_size
        self.payload = payload

# Response class and related enums
class Response:
    def __init__(self, opcode, payload_size, payload):
        self.version = 3
        self.opcode = opcode
        self.payload_size = payload_size
        self.payload = payload

# Enums for codes and sizes used by both Request and Response
class Size(enum.Enum):
    CLIENT_ID_SIZE = 16
    VERSION_SIZE = 1
    CODE_SIZE = 2
    PAYLOAD_SIZE_SIZE = 4
    NAME_SIZE = 255
    PUBLIC_KEY_SIZE = 160
    CONTENT_LENGTH_SIZE = 4
    ORIGINAL_FILE_LENGTH_SIZE = 4
    PACKET_NUMBER_SIZE = 2
    TOTAL_PACKETS_SIZE = 2
    FILE_NAME_SIZE = 255
    CHECKSUM_SIZE = 4

class Offset(enum.Enum):
    NAME_OFFSET = 0
    FILE_NAME_OFFSET = 0
    CONTENT_SIZE_OFFSET = 0
    ORIGINAL_FILE_SIZE_OFFSET = CONTENT_SIZE_OFFSET + Size.CONTENT_LENGTH_SIZE.value
    PACKET_NUMBER_OFFSET = ORIGINAL_FILE_SIZE_OFFSET + Size.ORIGINAL_FILE_LENGTH_SIZE.value
    TOTAL_PACKETS_OFFSET = PACKET_NUMBER_OFFSET + Size.PACKET_NUMBER_SIZE.value
    BACKUP_FILE_NAME_OFFSET = TOTAL_PACKETS_OFFSET + Size.TOTAL_PACKETS_SIZE.value
    MESSAGE_CONTENT_OFFSET = BACKUP_FILE_NAME_OFFSET + Size.FILE_NAME_SIZE.value

class Code(enum.Enum):
    REGISTRATION_SUCCESSFUL = 1600
    REGISTRATION_FAILED = 1601
    AES_KEY_EXCHANGE = 1602
    FILE_RECEIVED = 1603
    MESSAGE_RECEIVED = 1604
    LOGIN_SUCCESSFUL = 1605
    LOGIN_FAILED = 1606
    GENERAL_ERROR = 1607