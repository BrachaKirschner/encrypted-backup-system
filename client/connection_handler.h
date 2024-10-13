#ifndef CONNECTION_HANDLER_H
#define CONNECTION_HANDLER_H

#include <boost/asio.hpp>
#include <protocol.h>

using boost::asio::ip::tcp;

/**
* Class to handle the TCP connection, sending/receiving messages based on the protocol.
*/
class ConnectionHandler
{
public:
    /**
    * Constructor.
    * @param socket the socket to handle the connection.
    */
    ConnectionHandler();

    /**
    * Destructor.
    */
    ~ConnectionHandler();

    /**
     * Exchange messages with the server.
     * @param request the request to send to the server.
     * @return the response received from the server.
     */
    Response_t exchange_messages(const Request_t& request);

private:
    boost::asio::io_context io_context;
    tcp::socket socket;

    /**
    * Write a request to the server.
    * @param request the request to write.
    */
    void write_request(const Request_t& request);

    /**
    * Read a response from the server.
    * @return the response read.
    */
    Response_t read_response();
};

#endif //CONNECTION_HANDLER_H