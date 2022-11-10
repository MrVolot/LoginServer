#include "LoginServer.h"
#include "Database.h"
#include "ConnectionHandler.h"
#include "Commands.h"
#include <boost/bind.hpp>

LoginServer::LoginServer(boost::asio::io_service& service) : service_{ service },
acceptor_{ service, ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 10696) },
connection_{ nullptr }
{
	DatabaseHandler::getInstance().connectDB("Login_Server", "123");
	startAccept();
}

void LoginServer::handleAccept(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err)
{
	if (!err) {
		connection_->callAsyncRead();
	}
	startAccept();
}

void LoginServer::startAccept()
{
	connection_.reset(new ConnectionHandler<LoginServer>{ service_, *this });
	connection_->setAsyncReadCallback(&LoginServer::readHandle);
	connection_->setWriteCallback(&LoginServer::writeHandle);
	acceptor_.async_accept(connection_->getSocket(), boost::bind(&LoginServer::handleAccept, this, connection_, boost::asio::placeholders::error));
}

void LoginServer::readHandle(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err, size_t bytes_transferred)
{
	if (err) {
		connection->getSocket().close();
		return;
	}
	std::string data{ connection->getData() };
	auto status{ LoginParser::getInstance().processCredentials(data) };
	sendResponse(connection, status, LoginParser::getInstance().getUserId(data));
	connection->getStrBuf().reset(new boost::asio::streambuf);
	connection->setMutableBuffer();
	connection->callAsyncRead();
}

void LoginServer::writeHandle(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err, size_t bytes_transferred)
{
	if (err) {
		connection->getSocket().close();
		return;
	}
}

void LoginServer::sendResponse(std::shared_ptr<IConnectionHandler<LoginServer>> connection, credentialsStatus status, const std::string& userId)
{
	Json::Value value;
	Json::FastWriter writer;
	if (status == credentialsStatus::RIGHT_PASSWORD || status == credentialsStatus::SUCCESSFUL_REGISTRATION) {
		value["command"] = RIGHTCREDENTIALS;
		value["status"] = "true";
		value["token"] = LoginParser::getInstance().hash;
		connection->callWrite(writer.write(value));
		connection->getSocket().close();
		return;
	}
	if (status == credentialsStatus::AUTHORIZATION_SUCCEEDED) {
		value["command"] = AUTHSUCCESS;
		value["status"] = "true";
		value["token"] = LoginParser::getInstance().hash;
		connection->callWrite(writer.write(value));
		connection->getSocket().close();
		return;
	}
	if (status == credentialsStatus::AUTHORIZATION_FAILED) {
		value["command"] = AUTHFAIL;
		value["status"] = "false";
		value["token"] = LoginParser::getInstance().hash;
		connection->callWrite(writer.write(value));
		return;
	}
	if(status == credentialsStatus::USER_ALREADY_EXISTS){
		value["command"] = USERALREADYEXISTS;
		value["status"] = "false";
		connection->callWrite(writer.write(value));
		return;
	}
	value["command"] = WRONGCREDENTIALS;
	value["status"] = "false";
	connection->callWrite(writer.write(value));
}