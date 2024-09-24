#include <iostream>
#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include <CryptoPP/cryptlib.h>

using boost::asio::ip::tcp;

int main()
{
    // get info from 'transfer.info'
    std::string address = read_address("transfer.info");
    std::string port = read_port("transfer.info");
    std::string username = read_username("transfer.info");
    std::filesystem::path path = read_path("transfer.info");

    boost::asio::io_context io_context;
    tcp::socket socket(io_context);
    tcp::resolver resolver(io_context);
    boost::asio::connect(socket, resolver.resolve(address, port));

    if(std::filesystem::exists("me.info"))
    {
        register_user(socket, username);
        extchange_keys(socket, username);
        send_file(socket, path);

    }
    else
    {
        socket 
    }
    return 0;
}