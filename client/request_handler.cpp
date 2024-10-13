#include "request_handler.h"
#include "protocol.h"
#include "file_utils.h"
#include "AESWrapper.cpp"
#include "RSAWrapper.cpp"
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
    // open the file
    std::ifstream original_file(filename, std::ios::binary);
    if (!original_file.is_open())
    {
        throw std::runtime_error("File not found");
    }

    original_file.seekg(0, std::ios::end); // Move the get pointer to the end of the file to determine the file size
    std::streampos file_size = original_file.tellg(); // Get the file size
    original_file.seekg(0, std::ios::beg); // Move the get pointer back to the beginning of the file
    int packet_number = 0, total_packets = file_size / PACKET_SIZE;

    while(!original_file.eof())
    {
        char buffer[PACKET_SIZE];
        original_file.read(buffer, PACKET_SIZE);
        int cksum = compute_checksum(original_file); // compute the checksum

        AESWrapper aes_wrapper = AESWrapper(reinterpret_cast<const unsigned char*>(aes_key.c_str()), AES_KEY_SIZE);
        std::string encrypted_content = aes_wrapper.encrypt(buffer, PACKET_SIZE); // encrypt the file

        // declartion
        Request_t file_request, crc_request;
        Response_t response;
        int num_of_tries;

        // perparing the file request
        std::copy_n(client_id, CLIENT_ID_SIZE, file_request.client_id);
        file_request.code = SEND_FILE;
        file_request.append_to_payload(encrypted_content.size() , CONTENT_LENGTH_SIZE);
        file_request.append_to_payload(original_file.tellg(), CONTENT_LENGTH_SIZE);

        // GET THE PAYLOAD HERE: encrypted_file.size(), original_file.size(), packet_number, total_packets, filename, encrypted_file

        // perparing the crc request
        std::copy_n(client_id, CLIENT_ID_SIZE, crc_request.client_id);
        crc_request.append_to_payload(filename, FILE_NAME_SIZE);

        // sending the file
        for (num_of_tries = 0; num_of_tries < NUM_OF_TRIES + 1; num_of_tries++)
        {
            response = connection_handler.exchange_messages(file_request);
            if (response.code == FILE_RECEIVED)
            {
                int response_cksum;
                std::memcpy(&response_cksum, response.payload.data() + CKSUM_OFFSET, CKSUM_SIZE);
                if (cksum == response_cksum)
                {
                    crc_request.code = CORRECT_CRC;
                    response = connection_handler.exchange_messages(crc_request);
                    if (response.code == MESSAGE_RECEIVED)
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
        if (num_of_tries > NUM_OF_TRIES + 1)
        {
            crc_request.code = FOUTH_INCORRECT_CRC;
            response = connection_handler.exchange_messages(crc_request);
            throw std::runtime_error("incorrect crc fourth time");
        }
    }
}








void RequestHandler::register_user()
{
    // handle the registration request
    Request_t request;
    request.code = REGISTER;
    request.payload = std::vector<uint8_t>(username, username + NAME_SIZE);
    request.payload_size = request.payload.size();

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == REGISTRATION_SUCCESSFUL)
    {
        std::copy_n(response.payload, CLIENT_ID_SIZE, client_id);
        write_client_id("me.info", request.payload);
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
    request.payload = std::vector<uint8_t>(username, username + NAME_SIZE);
    request.payload_size = request.payload.size();

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == LOGIN_SUCCESSFUL)
    {
        rsa_key = read_rsa_key();
        decrypt_aes_key(rsa_key, response.payload);
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
    uint8_t rsa_private_key[RSA_KEY_SIZE], rsa_public_key[RSA_KEY_SIZE];
    rsa_private_wrapper.getPrivateKey((char *)rsa_private_key, RSA_KEY_SIZE);
    rsa_private_wrapper.getPublicKey((char *)rsa_public_key, RSA_KEY_SIZE);
    write_rsa_private_key();

    // Handle the exchange keys request
    Request_t request;
    std::copy_n(client_id, CLIENT_ID_SIZE, request.client_id);
    request.code = SEND_PUBLIC_KEY;
    request.append_to_payload(username, NAME_SIZE);
    request.append_to_payload(rsa_public_key, RSA_KEY_SIZE);

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == AES_KEY_EXCHANGE)
    {
        copy_n(response.payload.data() + AES_KEY_OFFSET, AES_KEY_SIZE, aes_key);
        aes_key = rsa_private_wrapper.decrypt(aes_key);
    }
    if (response.code == GENERAL_ERROR)
    {
        throw std::runtime_error("General server error");
    }
}

void RequestHandler::backup_file()
{
    // open the file
    std::ifstream original_file(filename, std::ios::binary);
    if (!original_file.is_open())
    {
        throw std::runtime_error("File not found");
    }

    int cksum = compute_checksum(original_file); // compute the checksum

    // reseting the file after computing the checksum to read it again from the beginning to encrypt it
    original_file.clear();
    original_file.seekg(0, std::ios::beg);

    std::ifstream encrypted_file = encrypt_file(original_file); // encrypt the file

    // declartion
    Request_t file_request, crc_request;
    Response_t response;
    int num_of_tries;

    // perparing the file request
    std::copy_n(client_id, CLIENT_ID_SIZE, file_request.client_id);
    file_request.code = SEND_FILE;
    // GET THE PAYLOAD HERE: encrypted_file.size(), original_file.size(), packet_number, total_packets, filename, encrypted_file
    file_payload.size = file_request.payload.size();

    // perparing the crc request
    std::copy_n(client_id, CLIENT_ID_SIZE, crc_request.client_id);
    crc_request.payload = std::vector<uint8_t>(filename, filename + FILE_NAME_SIZE);
    crc_request.payload_size = crc_request.payload.size();

    // sending the file
    for (num_of_tries = 0; num_of_tries < NUM_OF_TRIES + 1; num_of_tries++)
    {
        response = connection_handler.exchange_messages(file_request);
        if (response.code == FILE_RECEIVED)
        {
            int response_cksum;
            std::memcpy(&response_cksum, response.payload.data() + CKSUM_OFFSET, CKSUM_SIZE);
            if (cksum == response_cksum)
            {
                crc_request.code = CORRECT_CRC;
                response = connection_handler.exchange_messages(crc_request);
                if (response.code == MESSAGE_RECEIVED)
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
    if (num_of_tries > NUM_OF_TRIES + 1)
    {
        crc_request.code = FOUTH_INCORRECT_CRC;
        response = connection_handler.exchange_messages(crc_request);
        throw std::runtime_error("incorrect crc fourth time");
    }
}