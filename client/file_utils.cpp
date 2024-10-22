#include "file_utils.h"
#include "protocol.h"
#include "Base64Wrapper.h"
#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <regex>
#include <cstdint> // for UINT16_MAX
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <filesystem>

#define MAX_USERNAME_SIZE 100

std::string read_address()
{
    std::ifstream file("transfer.info");
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open transfer.info");
    }
    std::string line;
    std::getline(file, line);
    file.close();

    std::istringstream iss(line);
    std::string address;
    std::getline(iss, address, ':');
    
    // Regular expression for validating IP address or hostname
    std::regex ip_regex(R"((\d{1,3}\.){3}\d{1,3})"); // Simple regex for IPv4
    std::regex hostname_regex(R"((([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}))"); // Simple regex for hostname

    if(!std::regex_match(address, ip_regex) && !std::regex_match(address, hostname_regex))
    {
        throw std::runtime_error("Fatal: invalid address in transfer.info");
    }

    return address;
}

std::string read_port()
{
    std::ifstream file("transfer.info");
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open transfer.info");
    }
    std::string line;
    std::getline(file, line);
    file.close();

    std::istringstream iss(line);
    std::string port;
    std::getline(iss, port, ':');
    std::getline(iss, port, ':');

    // validate the port
    int port_int = std::stoi(port);
    if(port_int < 1 || port_int > UINT16_MAX)
    {
        throw std::runtime_error("Fatal: invalid port in transfer.info");
    }
    
    return port;
}

std::string read_username()
{
    std::ifstream file("transfer.info");
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open me.info");
    }
    std::string username;
    std::getline(file, username);
    std::getline(file, username);
    file.close();

    // validate the username
    if(username.size() > MAX_USERNAME_SIZE)
    {
        throw std::runtime_error("Fatal: username too long. Max length is " + MAX_USERNAME_SIZE);
    }

    return username;
}

std::string read_file_path()
{
    std::ifstream file("transfer.info");
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open me.info");
    }
    std::string file_path;
    std::getline(file, file_path);
    std::getline(file, file_path);
    std::getline(file, file_path);
    file.close();

    // validate the filename length
    std::filesystem::path path(file_path);
    if(path.filename().string().size() > FILE_NAME_SIZE - 1) // -1 for the null terminator
    {
        throw std::runtime_error("Fatal: filename too long. Max length is " + std::to_string(FILE_NAME_SIZE-1));
    }
    
    return file_path;
}

std::string read_client_id()
{
	std::ifstream file("me.info");
	if (!file.is_open())
	{
		throw std::runtime_error("Fatal: could not open me.info");
	}
	std::string hex_client_id;
	std::getline(file, hex_client_id);
	std::getline(file, hex_client_id); // read the client_id from the second line in me.info
	file.close();

	// convert the hex string to a byte string representing the client_id
    std::string client_id;
	for (size_t i = 0; i < hex_client_id.size(); i += 2)
	{
		std::string byte = hex_client_id.substr(i, 2);
		client_id.push_back(std::stoi(byte, nullptr, 16));
	}

	// validate the client_id
	if (client_id.size() != CLIENT_ID_SIZE)
	{
		throw std::runtime_error("Fatal: invalid client_id in me.info");
	}

	return client_id;
}


std::string read_rsa_key()
{
    std::ifstream file("priv.key");
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open rsa_key.pem");
    }
    std::string rsa_key;
    std::string line;
    while(std::getline(file, line))
    {
        rsa_key += line + '\n';
    }
    file.close();

    Base64Wrapper base64_wrapper;
    return base64_wrapper.decode(rsa_key);
}

void write_username(const std::string& username)
{
	std::ofstream file("me.info"); // append mode
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open me.info");
    }
	std::string username_copy = username;
	username_copy.pop_back(); // removing the null terminator
	file << username_copy << std::endl;
    file.close();
}

void write_client_id(const std::string& client_id)
{
    std::ofstream file("me.info", std::ios_base::app); // append mode
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open me.info");
    }
    std::ostringstream oss;
    for (unsigned char byte : client_id)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    file << oss.str() << std::endl;
    file.close();
}

void write_rsa_private_key(const std::string& rsa_private_key)
{
	std::ofstream file1("me.info", std::ios_base::app); // append mode
    if(!file1.is_open())
    {
        throw std::runtime_error("Fatal: could not open rsa_key.pem");
    }
    Base64Wrapper base64_wrapper;
    file1 << base64_wrapper.encode(rsa_private_key) << std::endl;
    file1.close();

    std::ofstream file2("priv.key");
    if(!file2.is_open())
    {
        throw std::runtime_error("Fatal: could not open rsa_key.pem");
    }
    file2 << base64_wrapper.encode(rsa_private_key) << std::endl;
    file2.close();
}