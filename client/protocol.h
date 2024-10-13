#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <vector>
#include <string>

// Protocol constants
const uint8_t PROTOCOL_VERSION = 3; // Shared protocol version

// Request Structure
typedef struct
{
    uint8_t client_id[16];
    uint8_t version = PROTOCOL_VERSION;
    uint16_t code;
    uint32_t payload_size;
    std::vector<uint8_t> payload;

    void append_to_payload(const std::string &data, size_t size)
    {
        if (data.empty() || size == 0)
        {
            return; // Invalid data or size
        }

        // Calculate the actual data size
        size_t data_size = std::min(size, data.size());

        // Append the actual data
        payload.insert(payload.end(), data.begin(), data.begin() + data_size);

        // Calculate the padding size
        size_t padding_size = size > data_size ? size - data_size : 0;

        // Append padding if necessary
        if (padding_size > 0)
        {
            payload.insert(payload.end(), padding_size, '\0'); // Padding with zeros
        }

        // Update payload size
        payload_size = static_cast<uint32_t>(payload.size());
    }
} Request_t;

// Response Structure
typedef struct
{
    uint8_t version = PROTOCOL_VERSION;
    uint16_t code;
    uint32_t payload_size;
    std::vector<uint8_t> payload;
} Response_t;

// Request Codes
enum RequestCode
{
    REGISTER = 825,
    SEND_PUBLIC_KEY = 826,
    LOGIN = 827,
    SEND_FILE = 828,
    CORRECT_CRC = 900,
    INCORRECT_CRC = 901,
    FOURTH_INCORRECT_CRC = 902,
};

// Response Codes
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

// Sizes and offsets
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
    CKSUM_SIZE = 4,
};

enum Offset
{
    CLIENT_ID_OFFSET = 0,
    CONTENT_LENGTH_OFFSET = CLIENT_ID_OFFSET + CLIENT_ID_SIZE,
    FILE_NAME_OFFSET = CONTENT_LENGTH_OFFSET + CONTENT_LENGTH_SIZE,
    CKSUM_OFFSET = FILE_NAME_OFFSET + FILE_NAME_SIZE,
    AES_KEY_OFFSET = CLIENT_ID_OFFSET + CLIENT_ID_SIZE,
};

#endif // PROTOCOL_H