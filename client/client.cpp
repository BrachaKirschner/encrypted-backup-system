#include "request_handler.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <locale>

int main() 
{
    try
    {
        RequestHandler request_handler;
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