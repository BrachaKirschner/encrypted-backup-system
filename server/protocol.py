import enum

class Request:
    """
    Request class

    Attributes:
    client_id: The client ID
    version: The version of the protocol
    opcode: The operation code
    payload_size: The size of the payload
    payload: The payload
    """
    def __init__(self, client_id, version, opcode, payload_size, payload):
        self.client_id = client_id
        self.version = version
        self.opcode = opcode
        self.payload_size = payload_size
        self.payload = payload

class Response:
    """
    Response class

    Attributes:
    version: The version of the protocol
    opcode: The operation code
    payload_size: The size of the payload
    payload: The payload
    """
    def __init__(self, opcode, payload_size, payload):
        self.version = 3
        self.opcode = opcode
        self.payload_size = payload_size
        self.payload = payload

class Size(enum.Enum):
    """The size of various fields in the protocol"""
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
    """The offset of various fields in the payload"""
    NAME_OFFSET = 0
    FILE_NAME_OFFSET = 0
    CONTENT_SIZE_OFFSET = 0
    PUBLIC_KEY_OFFSET =  Size.NAME_SIZE.value
    ORIGINAL_FILE_SIZE_OFFSET = Size.CONTENT_LENGTH_SIZE.value
    PACKET_NUMBER_OFFSET = Size.CONTENT_LENGTH_SIZE.value + Size.ORIGINAL_FILE_LENGTH_SIZE.value
    TOTAL_PACKETS_OFFSET = Size.CONTENT_LENGTH_SIZE.value + Size.ORIGINAL_FILE_LENGTH_SIZE.value + Size.PACKET_NUMBER_SIZE.value
    BACKUP_FILE_NAME_OFFSET = Size.CONTENT_LENGTH_SIZE.value + Size.ORIGINAL_FILE_LENGTH_SIZE.value + Size.PACKET_NUMBER_SIZE.value + Size.TOTAL_PACKETS_SIZE.value
    MESSAGE_CONTENT_OFFSET = Size.CONTENT_LENGTH_SIZE.value + Size.ORIGINAL_FILE_LENGTH_SIZE.value + Size.PACKET_NUMBER_SIZE.value + Size.TOTAL_PACKETS_SIZE.value + Size.FILE_NAME_SIZE.value

class Code(enum.Enum):
    """The operation codes"""
    REGISTRATION_SUCCESSFUL = 1600
    REGISTRATION_FAILED = 1601
    AES_KEY_EXCHANGE = 1602
    FILE_RECEIVED = 1603
    MESSAGE_RECEIVED = 1604
    LOGIN_SUCCESSFUL = 1605
    LOGIN_FAILED = 1606
    GENERAL_ERROR = 1607