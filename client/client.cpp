#include <iostream>
#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include <request_handler.h>

using boost::asio::ip::tcp;

void initialize_connection(tcp::socket& socket, const std::string& address, const std::string& port)
{
    boost::asio::io_context io_context;
    tcp::resolver resolver(io_context);
    boost::asio::connect(socket, resolver.resolve(address, port));
}

int main() 
{
    try
    {
        RequestHandler request_handler();
        // handling the user login/registration
        if(std::filesystem::exists("me.info"))
        {
            request_handler.login();
        }
        else
        {
            request_handler.register_user();
            request_handler.exchange_keys();
        }
        // handling the file backup
        request_handler.backup_file();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}