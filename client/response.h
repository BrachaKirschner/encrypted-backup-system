#ifndef RESPONSE_H
#define RESPONSE_H

#include <cstdint>
#include <vector>

typedef struct
{
    uint8_t version = 3;
    uint16_t code;
    uint32_t payload_size;
    std::vector<uint8_t> payload;
} Response_t;

enum ResponseCode
{
    REGISTRATION_SUCCESSFUL = 1600,
    REGISTRATION_FAILED = 1601,
    AES_KEY_EXCHANGE = 1602,
    FILE_RECEIVED = 1603,
    MESSAGE_RECEIVED = 1604,
    LOGIN_SUCCESSFUL = 1605,
    LOGIN_FAILED = 1606,
    GENERAL_ERROR = 1607,
};

enum Size
{
    VERSION_SIZE = 1,
    CODE_SIZE = 2,
    PAYLOAD_SIZE_SIZE = 4,
    CLIENT_ID_SIZE = 16,
    CONTENT_LENGTH_SIZE = 4,
    FILE_NAME_SIZE = 255,
    CKSUM_SIZE = 4,
};

enum offset
{
    CLIENT_ID_OFFSET = 0,
    CONTENT_LENGTH_OFFSET = CLIENT_ID_OFFSET + CLIENT_ID_SIZE,
    FILE_NAME_OFFSET = CONTENT_LENGTH_OFFSET + CONTENT_LENGTH_SIZE,
    CKSUM_OFFSET = FILE_NAME_OFFSET + FILE_NAME_SIZE,
    AES_KEY_OFFSET = CLIENT_ID_OFFSET + CLIENT_ID_SIZE,
};

#endif //RESPONSE_H