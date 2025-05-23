#include "protocol.h"
#include <cstring>
#include <string>
#include <boost/asio.hpp> // For nthol

void Request_t::append_to_payload(const std::string &data, size_t size)
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

void Request_t::assign_client_id(const std::string &client_id)
{
    if (client_id.size() != CLIENT_ID_SIZE)
    {
        return; // Invalid client ID size
    }
    
    std::copy(client_id.begin(), client_id.end(), this->client_id);
}

std::string Response_t::read_from_payload(size_t offset, size_t size)
{
    if (offset >= payload.size() || size == 0)
    {
        return ""; // Invalid offset or size
    }

    std::string data = std::string(payload.begin() + offset, payload.begin() + offset + size);

	// If the data is a checksum or file name, convert it to host byte order
    if (size == CKSUM_SIZE || size == CONTENT_LENGTH_SIZE)
    {
        uint32_t network_value;
		std::memcpy(&network_value, data.c_str(), sizeof(network_value));
		data = std::to_string(ntohl(network_value));
    }

    return data;
}