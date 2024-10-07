#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <vector>
#include <cstdint>

std::string read_address();
std::string read_port();
std::string read_username();
std::string read_filename();
void write_client_id(const std::string& filename, const std::vector<uint8_t>& client_id);

#endif // FILE_UTILS_H