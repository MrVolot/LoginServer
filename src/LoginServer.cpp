#include "LoginServer.h"
#include "Database.h"
#include "ConnectionHandler.h"
#include <boost/bind.hpp>
#include <iostream>

LoginServer::LoginServer(boost::asio::io_service& service): service_ { service }, acceptor_{ service, ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 10677) }
{
    DatabaseHandler::getInstance().connectDB();
    startAccept();
}

void LoginServer::handleAccept(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err)
{
    if (!err) {
		connection_->callRead();
		return;
    }
    startAccept();
}

void LoginServer::startAccept()
{
    connection_.reset(new ConnectionHandler<LoginServer>{ service_, *this});
	connection_->setReadCallback(&LoginServer::readHandle);
	connection_->setWriteCallback(&LoginServer::writeHandle);
    acceptor_.async_accept(connection_->getSocket(), boost::bind(&LoginServer::handleAccept, this, connection_, boost::asio::placeholders::error));
}

void LoginServer::readHandle(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err, size_t bytes_transferred)
{
	if (err) {
		connection_->getSocket().close();
		return;
	}
 	std::string data{ boost::asio::buffer_cast<const char*>(connection_->getStrBuf()->data()) };
	auto status{ LoginParser::getInstance().processCredentials(data) };
	sendResponse(status);
	connection_->getStrBuf().reset(new boost::asio::streambuf);
	connection_->setMutableBuffer();
	connection_->callRead();
}

void LoginServer::writeHandle(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err, size_t bytes_transferred)
{
	if (err) {
		std::cout << err.message();
		connection_->getSocket().close();
		return;
	}
}

void LoginServer::sendResponse(credentialsStatus status)
{
	Json::Value value;
	Json::FastWriter writer;
	value["command"] = "response";
	if (status == credentialsStatus::RIGHT_PASSWORD || status == credentialsStatus::USER_REGISTERED || status == credentialsStatus::RIGHT_TOKEN) {
		value["status"] = "true";
		value["token"] = LoginParser::getInstance().hash;
		connection_->callWrite(writer.write(value));
		return;
	}
	value["status"] = "false";
	connection_->callWrite(writer.write(value));
}
