#include <boost/asio.hpp>
#include <boost/optional/optional.hpp>
#include "LoginServer.h"
#include "Database.h"
#include <iostream>

int main() {
    //boost::asio::io_service io_service;
    //LoginServer server{ io_service };
    //boost::optional<boost::asio::io_service::work> work;
    //work.emplace(io_service);
    ////work = boost::none;
    //io_service.run();
    nanodbc::connection connection{ "SQLDB", "Login_Server", "123" };
    std::cout << "CONNECTED! " << connection.driver_name() << std::endl;
    auto result{ nanodbc::execute(connection, "SELECT * FROM CONTACTS") };
    std::cout << result.columns() << " " << std::endl;


}