#include "request_handler.h"
#include "protocol.h"
#include "file_utils.h"
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include "cksum.h"
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <filesystem>

#define NUM_OF_TRIES 3
#define RSA_KEY_BITS_SIZE 1024
#define PACKET_SIZE 1024
#define AES_KEY_SIZE 32

RequestHandler::RequestHandler()
	: connection_handler(), username(), filename(), client_id(), private_rsa_key(), aes_key()
{
    username = read_username() + '\0';
    file_path = read_file_path();
    std::filesystem::path path(file_path);
    filename = path.filename().string();
}

RequestHandler::~RequestHandler()
{
	// destructor
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
        client_id = response.read_from_payload(CLIENT_ID_OFFSET, CLIENT_ID_SIZE);
        write_username(username);
        write_client_id(client_id);
		std::cout << "User " << username << " registered successfully" << std::endl;
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
	client_id = read_client_id();
    request.assign_client_id(client_id);
    request.code = LOGIN;
    request.append_to_payload(username, NAME_SIZE);

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == LOGIN_SUCCESSFUL)
    {
        std::string rsa_key = read_rsa_key();
        aes_key = response.read_from_payload(AES_KEY_OFFSET, response.payload_size - AES_KEY_OFFSET);
        RSAPrivateWrapper rsa_private_wrapper = RSAPrivateWrapper(rsa_key);
        aes_key = rsa_private_wrapper.decrypt(aes_key);
		std::cout << "User " << username << " logged in successfully" << std::endl;
    }
    if (response.code == LOGIN_FAILED)
    {
		std::filesystem::remove("me.info");
		std::filesystem::remove("priv.key");
		std::cout << "User " << username << " not found, registering..." << std::endl;
        register_user();
        exchange_keys();
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
    request.assign_client_id(client_id);
    request.code = SEND_PUBLIC_KEY;
    request.append_to_payload(username, NAME_SIZE);
    request.append_to_payload(rsa_public_key, PUBLIC_KEY_SIZE);

    Response_t response = connection_handler.exchange_messages(request);
    if (response.code == AES_KEY_EXCHANGE)
    {
        aes_key = response.read_from_payload(AES_KEY_OFFSET, response.payload_size - AES_KEY_OFFSET);
        aes_key = rsa_private_wrapper.decrypt(aes_key);
		std::cout << "AES key exchanged successfully" << std::endl;
    }
    if (response.code == GENERAL_ERROR)
    {
        throw std::runtime_error("General server error");
    }
}

void RequestHandler::backup_file()
{
    // opening the file
	std::ifstream original_file(file_path, std::ios::binary);
    if (!original_file.is_open())
    {
        throw std::runtime_error("File not found");
    }

    //computing the original file checksum
    std::string cksum_string = compute_file_crc(file_path);
    unsigned long int cksum = std::stoul(cksum_string.substr(0, cksum_string.find('\t')));

	// encrypting the file
	AESWrapper aes_wrapper = AESWrapper(reinterpret_cast<const unsigned char*>(aes_key.c_str()), AES_KEY_SIZE);
    std::string encrypted_filename = aes_wrapper.encrypt_file(file_path);
	original_file.close(); // closing the original file

	// opening the encrypted file
	std::ifstream encrypted_file(encrypted_filename, std::ios::binary);
	if (!encrypted_file.is_open())
	{
		throw std::runtime_error("File not found");
	}

	// getting the file sizes
	std::filesystem::path original_file_path(file_path);
	size_t original_file_size = std::filesystem::file_size(original_file_path);
	std::filesystem::path encrypted_file_path(encrypted_filename);
	size_t encrypted_file_size = std::filesystem::file_size(encrypted_file_path);


    // The client will try to send the file until it receives a correct CRC from the server or until it reaches the maximum number of attempts
	// The file will be sent in packets and client will only wait for the last packet to be acknowledged by the server
	for (size_t i = 0; i <= NUM_OF_TRIES; i++)
    {
		// packet preparation
        size_t packet_number = 1, total_packets = encrypted_file_size / PACKET_SIZE;
		if (encrypted_file_size % PACKET_SIZE != 0) // if the last packet is not full
        {
            total_packets++;
        }

        while(!encrypted_file.eof())
        {
            char buffer[PACKET_SIZE];
            encrypted_file.read(buffer, PACKET_SIZE);

			std::string buffer_string = std::string(buffer, encrypted_file.gcount());

            // preparing the file request
            Request_t file_request;
            file_request.assign_client_id(client_id);
            file_request.code = SEND_FILE;
            file_request.append_to_payload(std::to_string(encrypted_file_size), CONTENT_LENGTH_SIZE);
            file_request.append_to_payload(std::to_string(original_file_size), ORIGINAL_FILE_LENGTH_SIZE);
            file_request.append_to_payload(std::to_string(packet_number), PACKET_NUMBER_SIZE);
            file_request.append_to_payload(std::to_string(total_packets), TOTAL_PACKETS_SIZE);
            file_request.append_to_payload(filename, FILE_NAME_SIZE);
            file_request.append_to_payload(buffer_string, buffer_string.size());

            // sending the final packet
            if(packet_number == total_packets)
            {
				// getting rid of the encrypted file
				encrypted_file.close();
				std::filesystem::remove(encrypted_filename);

                Response_t response = connection_handler.exchange_messages(file_request);
                if(response.code == FILE_RECEIVED)
                {
                    unsigned long int response_cksum = std::stoul(response.read_from_payload(CKSUM_OFFSET, CKSUM_SIZE));
                    if(cksum == response_cksum)
                    {
						// preparing the CRC correct request
                        Request_t crc_request;
                        crc_request.assign_client_id(client_id);
                        crc_request.code = CORRECT_CRC;
                        crc_request.append_to_payload(filename, FILE_NAME_SIZE);
                        Response_t crc_response = connection_handler.exchange_messages(crc_request);
                        if(crc_response.code == MESSAGE_RECEIVED)
                        {
							std::cout << "File " << filename << " size: " << original_file_size << " bytes backed up successfully" << std::endl;
							return;
                        }
                    }
                    else
                    {
                        Request_t crc_request;
                        crc_request.assign_client_id(client_id);
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
    }

	// If the client failed to send the file after the maximum number of attempts, that is, it didn't return yet, 
	// it will send a request to the server to inform it that the file could not be backed up, and then it will throw an exception
    Request_t crc_request;
    crc_request.assign_client_id(client_id);
    crc_request.code = FOURTH_INCORRECT_CRC;
    crc_request.append_to_payload(filename, FILE_NAME_SIZE);
    Response_t crc_response = connection_handler.exchange_messages(crc_request);
    throw std::runtime_error("incorrect crc for the fourth time - file not backed up");
}