import enum


class Request:
    def __init__(self, client_id, version, opcode, payload_size, payload):
        self.client_id = client_id
        self.version = version
        self.opcode = opcode
        self.payload_size = payload_size
        self.payload = payload

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

class Offset(enum.Enum):
    NAME_OFFSET = 0
    FILE_NAME_OFFSET = 0
    PUBLIC_KEY_OFFSET = NAME_OFFSET.value + Size.NAME_SIZE.value
    CONTENT_SIZE_OFFSET = 0
    ORIGINAL_FILE_SIZE_OFFSET = CONTENT_SIZE_OFFSET.value + Size.CONTENT_LENGTH_SIZE.value
    PACKET_NUMBER_OFFSET = ORIGINAL_FILE_SIZE_OFFSET.value + Size.ORIGINAL_FILE_LENGTH_SIZE.value
    TOTAL_PACKETS_OFFSET = PACKET_NUMBER_OFFSET.value + Size.PACKET_NUMBER_SIZE.value
    BACKUP_FILE_NAME_OFFSET = TOTAL_PACKETS_OFFSET.value + Size.TOTAL_PACKETS_SIZE.value # This offset will only be used for accessing the file name in the payload of the backup file request
    MESSAGE_CONTENT_OFFSET = BACKUP_FILE_NAME_OFFSET.value + Size.FILE_NAME_SIZE.value