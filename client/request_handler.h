#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include <boost/asio.hpp>
#include <protocol.h>
#include <filesystem>
#include <cstdint>
#include "connection_handler.h"
#define AES_KEY_SIZE 32
#define RSA_KEY_SIZE 128

class RequestHandler
{
public:
    RequestHandler();
    ~RequestHandler();

    void login();
    void register_user();
    void exchange_keys();
    void backup_file();
private:
    ConnectionHandler connection_handler;
    std::string username;
    std::string filename;
    std::string client_id;
    std::string private_rsa_key;
    std::string aes_key;
};

#endif //REQUEST_HANDLER_H