#include "file_utils.h"
#include "request.h"
#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <regex>
#include <cstdint> // for UINT16_MAX

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
    if(username.size() > NAME_SIZE-1) // -1 for the null terminator
    {
        throw std::runtime_error("Fatal: username too long. Max length is " + std::to_string(NAME_SIZE-1));
    }

    return username;
}

std::string read_filename()
{
    std::ifstream file("transfer.info");
    if(!file.is_open())
    {
        throw std::runtime_error("Fatal: could not open me.info");
    }
    std::string filename;
    std::getline(file, filename);
    std::getline(file, filename);
    std::getline(file, filename);
    file.close();

    // validate the filename
    if(filename.size() > FILE_NAME_SIZE-1) // -1 for the null terminator
    {
        throw std::runtime_error("Fatal: filename too long. Max length is " + std::to_string(FILE_NAME_SIZE-1));
    }
    
    return filename;
}