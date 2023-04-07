#pragma once
#include "IConnectionHandler.h"
#include "LoginParser.h"
#include <boost/asio/ssl.hpp>

using namespace boost::asio;

class LoginServer {
    boost::asio::io_service& service_;
    boost::asio::ssl::context ssl_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<IConnectionHandler<LoginServer>> connection_;
public:
    LoginServer(boost::asio::io_service& service);
    void handleAccept(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err);
    void startAccept();
    void readHandle(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err, size_t bytes_transferred);
    void writeHandle(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err, size_t bytes_transferred);
    void sendResponse(std::shared_ptr<IConnectionHandler<LoginServer>> connection, credentialsStatus status, const std::string& userId);
};