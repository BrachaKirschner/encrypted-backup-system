#ifndef REQUEST_H
#define REQUEST_H

#include <cstdint>
#include <vector>

typedef struct
{
    uint8_t client_id[16];
    uint8_t version = 3;
    uint16_t code;
    uint32_t payload_size;
    std::vector<uint8_t> payload;
} Request_t;

enum RequestCode
{
    REGISTER = 825,
    SEND_PUBLIC_KEY = 826,
    LOGIN = 827,
    SEND_FILE = 828,
    CORRECT_CRC = 900,
    INCORRECT_CRC = 901,
    FOUTH_INCORRECT_CRC = 902,
};

enum Size
{
    CLIENT_ID_SIZE = 16,
    VERSION_SIZE = 1,
    CODE_SIZE = 2,
    PAYLOAD_SIZE_SIZE = 4,
    NAME_SIZE = 255,
    PUBLIC_KEY_SIZE = 160,
    CONTENT_LENGTH_SIZE = 4,
    ORIGINAL_FILE_LENGTH_SIZE = 4,
    PACKET_NUMBER_SIZE = 2,
    TOTAL_PACKETS_SIZE = 2,
    FILE_NAME_SIZE = 255,
};

#endif //REQUEST_H