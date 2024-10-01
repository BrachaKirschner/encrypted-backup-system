#include "request_handler.h"
#include "request.h"
#include "response.h"
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>

#define NUM_OF_TRIES 3

using boost::asio::ip::tcp;

RequestHandler::RequestHandler(tcp::socket& socket)
    : ConnectionHandler(SOCKET_SECURITY_PROTOCOL_INVALID)
{
    username = read_username();
    filename = read_filename();
}

void RequestHandler::register_user()
{
    // handle the registration request
    Request_t request;
    request.code = REGISTER;
    request.payload = username;
    request.payload_size = request.payload.size();

    Response_t response = connection_handler.exchange_messages(request);
    if(response.code == REGISTERTION_SUCCESSFUL)
    {
        client_id = response.payload;
        write_client_id("me.info", request.payload);
        // do something with AES key
    }
}

void RequestHandler::login()
{
    // handle the login request
    Request_t request;
    request.code = LOGIN;
    request.payload = std::vector<uint8_t>(username, username + NAME_SIZE);
    request.payload_size = request.payload.size();

    Response_t response = connection_handler.exchange_messages(request);
    if(response.code == LOGIN_SUCCESSFUL)
    {
        // do something with AES key
    }
    if(response.code == LOGIN_FAILED)
    {
        register_user();
    }
}

void RequestHandler::exchange_keys()
{

}

void RequestHandler::backup()
{
    // open the file
    std::ifstream original_file(filename, std::ios::binary);
    if(!original_file.is_open())
    {
        throw std::runtime_error("File not found");
    }

    int cksum = compute_checksum(original_file); // compute the checksum
    std::ifstream encrypted_file = encrypt_file(original_file); // encrypt the file
    
    // declartion
    Request_t file_request, crc_request;
    Response_t response;
    int num_of_tries;

    // perparing the file request
    file_request.client_id = client_id;
    file_request.code = SEND_FILE;
    // GET THE PAYLOAD HERE: encrypted_file.size(), original_file.size(), packet_number, total_packets, filename, encrypted_file
    file_payload.size = file_request.payload.size();

    // perparing the crc request
    crc_request.client_id = client_id;
    crc_request.payload = filename;
    crc_request.payload_size = crc_request.payload.size();

    // sending the file
    for(num_of_tries = 0; num_of_tries < NUM_OF_TRIES + 1; num_of_tries++)
    {
        response = connection_handler.exchange_messages(file_request);
        if(response.code == FILE_RECEIVED)
        {
            int response_cksum;
            std::memcpy(&response_cksum, response.payload.data() + CKSUM_OFFSET, CKSUM_SIZE);
            if(cksum == response_cksum)
            {
                crc_request.code = CORRECT_CRC;
                response = connection_handler.exchange_messages(crc_request);
                if(response.code == MESSAGE_RECEIVED)
                {
                    std::cout << "File backed up successfully" << std::endl;
                }
            }
            else
            {
                crc_request.code = INCORRECT_CRC;
                response = connection_handler.exchange_messages(crc_request);
            }
        }
    }
    if(num_of_tries > NUM_OF_TRIES + 1)
    {
        crc_request.code = FOUTH_INCORRECT_CRC;
        response = connection_handler.exchange_messages(crc_request);
        throw std::runtime_error("incorrect crc fourth time");
    }
}