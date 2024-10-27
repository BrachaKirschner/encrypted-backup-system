#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include "connection_handler.h"

/**
 * Class to handle the user requests.
 */
class RequestHandler
{
public:
	/**
	 * Constructor.
	 */
    RequestHandler();

	/**
	 * Destructor.
	 */
    ~RequestHandler();

	/**
	 * Handle the user login.
	 */
    void login();

	/**
	 * Handle the user registration.
     */
    void register_user();

    /**
	 * Handle the exchange keys request.
     */
    void exchange_keys();

	/**
	 * Handle the file backup.
     */
    void backup_file();
private:
    ConnectionHandler connection_handler;
    std::string username;
    std::string filename;
    std::string file_path;
    std::string client_id;
    std::string private_rsa_key;
    std::string aes_key;
};

#endif //REQUEST_HANDLER_H