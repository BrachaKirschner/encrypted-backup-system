#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <vector>
#include <string>

// Protocol constants
const uint8_t PROTOCOL_VERSION = 3; // Shared protocol version

// Request Structure
struct Request_t
{
    uint8_t client_id[16] = {0};
    uint8_t version = PROTOCOL_VERSION;
    uint16_t code = 0;
    uint32_t payload_size = 0;
    std::vector<uint8_t> payload;

    /**
	 * Assigns the client id to the request.
	 * @param client_id the client id to assign.
     */
    void assign_client_id(const std::string &client_id);

	/**
	 * Appends data to the end of the payload.
     * If the data size is smaller than the size parameter, the rest of the payload will be padded with zeros.
	 * If the data size is larger than the size parameter, the data will be truncated.
	 * @param data the data to append.
	 * @param size the size of the data to append.
	 */
    void append_to_payload(const std::string &data, size_t size);
};

// Response Structure
struct Response_t
{
    uint8_t version = PROTOCOL_VERSION;
    uint16_t code = 0;
	uint32_t payload_size = 0;
    std::vector<uint8_t> payload;

	/**
	 * Reads data from the payload.
	 * @param offset the offset to start reading from the payload.
	 * @param size the size of the data to read.
	 * @return the data read.
     */
    std::string read_from_payload(size_t offset, size_t size);
};

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