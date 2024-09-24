#include <cstdint>
#include <vector>

typedef struct
{
    uint8_t client_id[16];
    const uint8_t version = 3;
    uint16_t code;
    uint32_t payload_size;
    std::vector<uint8_t> payload;
} Request_t;
