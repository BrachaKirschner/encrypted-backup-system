#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include <boost/asio.hpp>
#include <request.h>
#include <filesystem>
#include <cstdint>
#include "connection_handler.h"

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
    uint8_t username[NAME_SIZE];
    uint8_t filename[FILE_NAME_SIZE];
    uint8_t client_id[CLIENT_ID_SIZE];

    int compute_checksum(const std::ifstream& file);
    std::ifstream encrypt_file(const std::ifstream& file);
};

#endif //REQUEST_HANDLER_H