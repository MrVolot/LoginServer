#pragma once
#include <boost/asio.hpp>
#include "LoginParser.h"

class LoginConnectionHandler: public std::enable_shared_from_this<LoginConnectionHandler> {
    boost::asio::ip::tcp::socket socket_;
    boost::asio::io_service& service_;
    const size_t msgLength{ 1024 };
    std::unique_ptr<boost::asio::streambuf> strBuf;
    boost::asio::streambuf::mutable_buffers_type mutableBuffer;
public:
    LoginConnectionHandler(boost::asio::io_service& service);
    boost::asio::ip::tcp::socket& getSocket();
    void start();
    void readHandle(const boost::system::error_code& err, size_t bytes_transferred);
    void writeHandle(const boost::system::error_code& err, size_t bytes_transferred);
    static std::shared_ptr<LoginConnectionHandler> create(boost::asio::io_service& service);
    void writeMessage(const std::string& str);
    void sendResponse(credentialsStatus status);
};