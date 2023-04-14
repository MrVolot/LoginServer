#include <boost/asio.hpp>
#include <boost/optional/optional.hpp>
#include "LoginServer.h"
#include "Database.h"
#include <iostream>

int main() {
    try {
        boost::asio::io_service io_service;
        LoginServer server{ io_service };
        boost::optional<boost::asio::io_service::work> work;
        work.emplace(io_service);
        io_service.run();
    }
    catch (std::exception& ex) {
        std::cout << ex.what();
    }
}