#include "request_handler.h"
#include "protocol.h"
#include "file_utils.h"
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include "cksum.h"
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>

#define NUM_OF_TRIES 3
#define RSA_KEY_BITS_SIZE 1024
#define PACKET_SIZE 1024

RequestHandler::RequestHandler()
    : connection_handler()
{
    std::string user_n = read_username();
    std::copy_n(user_n, NAME_SIZE, username);
    username[user_n.size()] = '\0';

    std::string file_n = read_filename();
    std::copy_n(file_n, FILE_NAME_SIZE, filename);
    filename[file_n.size()] = '\0';
}

void RequestHandler::register_user()
{
    // handle the registration request
    Request_t request;
    request.code = REGISTER;
    request.append_to_payload(username, NAME_SIZE);   

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == REGISTRATION_SUCCESSFUL)
    {
        std::copy_n(response.payload, CLIENT_ID_SIZE, client_id);
        write_username(username);
        write_client_id(client_id);
    }
    if (response.code == REGISTRATION_FAILED)
    {
        throw std::runtime_error("Registration failed");
    }
    if (response.code == GENERAL_ERROR)
    {
        throw std::runtime_error("General server error");
    }
}

void RequestHandler::login()
{
    // handle the login request
    Request_t request;
    std::copy_n(client_id, CLIENT_ID_SIZE, request.client_id);
    request.code = LOGIN;
    request.append_to_payload(username, NAME_SIZE);

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == LOGIN_SUCCESSFUL)
    {
        std::string rsa_key = read_rsa_key();
        std::copy_n(response.payload.begin() + AES_KEY_OFFSET, AES_KEY_SIZE, aes_key);
        RSAPrivateWrapper rsa_private_wrapper = RSAPrivateWrapper(rsa_key);
        rsa_private_wrapper.decrypt(aes_key);
    }
    if (response.code == LOGIN_FAILED)
    {
        register_user();
    }
    if (response.code == GENERAL_ERROR)
    {
        throw std::runtime_error("General server error");
    }
}

void RequestHandler::exchange_keys()
{
    // Generate RSA keys
    RSAPrivateWrapper rsa_private_wrapper = RSAPrivateWrapper();
    std::string rsa_private_key = rsa_private_wrapper.getPrivateKey();
    std::string rsa_public_key = rsa_private_wrapper.getPublicKey();
    write_rsa_private_key(rsa_private_key);

    // Handle the exchange keys request
    Request_t request;
    std::copy_n(client_id, CLIENT_ID_SIZE, request.client_id);
    request.code = SEND_PUBLIC_KEY;
    request.append_to_payload(username, NAME_SIZE);
    request.append_to_payload(rsa_public_key, RSA_KEY_SIZE);

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == AES_KEY_EXCHANGE)
    {
        std::copy_n(response.payload.begin() + AES_KEY_OFFSET, AES_KEY_SIZE, aes_key);
        aes_key = rsa_private_wrapper.decrypt(aes_key);
    }
    if (response.code == GENERAL_ERROR)
    {
        throw std::runtime_error("General server error");
    }
}

void RequestHandler::backup_file()
{
    // opening the file
    std::ifstream original_file(filename, std::ios::binary);
    if (!original_file.is_open())
    {
        throw std::runtime_error("File not found");
    }

    //computing the original file checksum
    std::string cksum_string = readfile(filename);
    int  cksum = std::stoi(cksum_string.substr(0, cksum_string.find('\t')));

    // getting the file size
    original_file.seekg(0, std::ios::end); // Move the get pointer to the end of the file to determine the file size
    std::streampos original_file_size = original_file.tellg(); // Get the file size
    original_file.seekg(0, std::ios::beg); // Move the get pointer back to the beginning of the file

    size_t encrypted_file_size = 0, original_file_size = 0;

    // encrypting the file
    AESWrapper aes_wrapper = AESWrapper(reinterpret_cast<const unsigned char*>(aes_key.c_str()), AES_KEY_SIZE);
    std::fstream encrypted_file(filename + ".enc", std::ios::binary);
    while (!original_file.eof())
    {
        // reading chunk of the file and encrypting it
        char buffer[PACKET_SIZE];
        original_file.read(buffer, PACKET_SIZE);
        std::string encrypted_content = aes_wrapper.encrypt(buffer, PACKET_SIZE);
        encrypted_file.write(encrypted_content.c_str(), encrypted_content.size());

        // updating the sizes
        original_file_size += original_file.gcount();
        encrypted_file_size += encrypted_content.size();
    }

    // The client will try to send the file until it receives a correct CRC from the server or until it reaches the maximum number of attempts
    // The file will be sent in packets of and client will only wait for the last packet to be acknowledged
    unsigned short int num_of_attempts = 0;
    do
    {
        encrypted_file.seekg(0, std::ios::beg); // Move the get pointer back to the beginning of the file
        
        // preparing the file request
        unsigned int packet_number = 0, total_packets = encrypted_file_size / PACKET_SIZE;
        if (encrypted_file_size % PACKET_SIZE != 0)
        {
            total_packets++;
        }

        while(!encrypted_file.eof())
        {
            char buffer[PACKET_SIZE];
            encrypted_file.read(buffer, PACKET_SIZE);
            
            // preparing the file request
            Request_t file_request;
            std::copy_n(client_id, CLIENT_ID_SIZE, file_request.client_id);
            file_request.code = SEND_FILE;
            file_request.append_to_payload(std::to_string(encrypted_file_size), CONTENT_LENGTH_SIZE);
            file_request.append_to_payload(std::to_string(original_file_size), CONTENT_LENGTH_SIZE);
            file_request.append_to_payload(std::to_string(packet_number), PACKET_NUMBER_SIZE);
            file_request.append_to_payload(std::to_string(total_packets), TOTAL_PACKETS_SIZE);
            file_request.append_to_payload(filename, FILE_NAME_SIZE);
            file_request.append_to_payload(buffer, encrypted_file.gcount());

            // sending the file packet
            if(packet_number == total_packets - 1)
            {
                Response_t response = connection_handler.exchange_messages(file_request);
                if(response.code == FILE_RECEIVED)
                {
                    int response_cksum;
                    std::memcpy(&response_cksum, response.payload.data() + CKSUM_OFFSET, CKSUM_SIZE);
                    if(cksum == response_cksum)
                    {
                        Request_t crc_request;
                        std::copy_n(client_id, CLIENT_ID_SIZE, crc_request.client_id);
                        crc_request.code = CORRECT_CRC;
                        crc_request.append_to_payload(filename, FILE_NAME_SIZE);
                        Response_t crc_response = connection_handler.exchange_messages(crc_request);
                        if(crc_response.code == MESSAGE_RECEIVED)
                        {
                            std::cout << "File backed up successfully" << std::endl;
                        }
                    }
                    else
                    {
                        Request_t crc_request;
                        std::copy_n(client_id, CLIENT_ID_SIZE, crc_request.client_id);
                        crc_request.code = INCORRECT_CRC;
                        crc_request.append_to_payload(filename, FILE_NAME_SIZE);
                        Response_t crc_response = connection_handler.exchange_messages(crc_request);
                    }
                }
            }
            else
            {
                connection_handler.write_request(file_request);
                packet_number++;
            }
        }
    } while (++num_of_attempts == NUM_OF_TRIES);

    // if the client reaches the maximum number of attempts, it will send a request to the server to inform it that the file will not be sent
    if(num_of_attempts == NUM_OF_TRIES)
    {
        Request_t crc_request;
        std::copy_n(client_id, CLIENT_ID_SIZE, crc_request.client_id);
        crc_request.code = FOURTH_INCORRECT_CRC;
        crc_request.append_to_payload(filename, FILE_NAME_SIZE);
        Response_t crc_response = connection_handler.exchange_messages(crc_request);
        throw std::runtime_error("incorrect crc for the fourth time - file not backed up");
    }
}