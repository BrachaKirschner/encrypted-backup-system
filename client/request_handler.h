#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

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
    std::string username;
    std::string filename;
    std::string client_id;
    std::string private_rsa_key;
    std::string aes_key;
};

#endif //REQUEST_HANDLER_H