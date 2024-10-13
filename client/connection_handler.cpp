#include "connection_handler.h"
#include "protocol.h"
#include "file_utils.h"
#include <boost/asio.hpp>
#include <cstdint>
#include <iostream>

#define NUM_OF_TRIES 3

using boost::asio::ip::tcp;

ConnectionHandler::ConnectionHandler()
    : socket(io_context)
{
    tcp::resolver resolver(io_context);
    boost::asio::connect(socket, resolver.resolve(read_address(), read_port()));
}

ConnectionHandler::~ConnectionHandler()
{
    socket.close();
}

Response_t ConnectionHandler::exchange_messages(const Request_t& request)
{
    for (int i = 0; i < NUM_OF_TRIES; i++)
    {
        write_request(request);
        Response_t response = read_response();
        if (response.code != GENERAL_ERROR)
        {
            return response;
        }
        if(i == NUM_OF_TRIES - 1)
        {
            std::string error_message = "Fatal: message " + std::to_string(request.code) + " responded with error 3 times";
            throw std::runtime_error(error_message);
        }
        std::cout << "Server responded with an error" << std::endl;
    }
}

void ConnectionHandler::write_request(const Request_t& request)
{
    boost::asio::write(socket, boost::asio::buffer(&request.client_id, CLIENT_ID_SIZE));
    boost::asio::write(socket, boost::asio::buffer(&request.version, VERSION_SIZE));
    uint16_t code_network = htons(request.code);
    boost::asio::write(socket, boost::asio::buffer(&code_network, CODE_SIZE));
    uint32_t payload_size_network = htonl(request.payload_size);
    boost::asio::write(socket, boost::asio::buffer(&payload_size_network, PAYLOAD_SIZE_SIZE));
    boost::asio::write(socket, boost::asio::buffer(request.payload));
}

Response_t ConnectionHandler::read_response()
{
    Response_t response;
    boost::asio::read(socket, boost::asio::buffer(&response.version, VERSION_SIZE));
    boost::asio::read(socket, boost::asio::buffer(&response.code, CODE_SIZE));
    response.code = ntohs(response.code);
    boost::asio::read(socket, boost::asio::buffer(&response.payload_size, PAYLOAD_SIZE_SIZE));
    response.payload_size = ntohl(response.payload_size);
    response.payload.resize(response.payload_size);
    boost::asio::read(socket, boost::asio::buffer(response.payload));
    return response;
}