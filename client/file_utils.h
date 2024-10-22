#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * Read the address of the server from the transfer.info file.
 * The function validates the address.
 * @return the address read.
 */
std::string read_address();

/**
 * Read the port of the server from the transfer.info file.
 * The function validates the port.
 * @return the port read.
 */
std::string read_port();

/**
 * Read the username from the transfer.info file.
 * The function validates the username size.
 * @return the username read.
 */
std::string read_username();

/**
 * Read the file path from the transfer.info file.
 * @return the file path read.
 */
std::string read_file_path();

/**
 * Read the client id from the me.info file.
 * @return the client id read.
 */
std::string read_client_id();

/**
 * Read the private RSA key from the priv.key file.
 * @return the RSA key read.
 */
std::string read_rsa_key();

/**
 * Write the username to the me.info file.
 * @param username the username to write.
 */
void write_username(const std::string& username);

/**
 * Write the client id to the me.info file.
 * @param client_id the client id to write.
 */
void write_client_id(const std::string& client_id);

/**
 * Write the RSA private key to the priv.key and me.info files.
 * @param rsa_private_key the RSA private key to write.
 */
void write_rsa_private_key(const std::string& rsa_private_key);

#endif // FILE_UTILS_H