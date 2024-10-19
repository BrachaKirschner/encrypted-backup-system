#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <vector>
#include <cstdint>

std::string read_address();
std::string read_port();
std::string read_username();
std::string read_filename();
std::string read_rsa_key();
void write_username(const std::string& username);
void write_client_id(const std::string& client_id);
void write_rsa_private_key(const std::string& rsa_private_key);

#endif // FILE_UTILS_H