#include "LoginConnectionHandler.h"
#include "Database1.h"
#include <boost/bind.hpp>

LoginConnectionHandler::LoginConnectionHandler(boost::asio::io_service& service) : socket_{ service },
service_{ service }, strBuf{ new boost::asio::streambuf }, mutableBuffer{ strBuf->prepare(msgLength) } 
{
}

boost::asio::ip::tcp::socket& LoginConnectionHandler::getSocket()
{
	return socket_;
}

void LoginConnectionHandler::start()
{
	socket_.async_read_some(boost::asio::buffer(mutableBuffer), boost::bind(&LoginConnectionHandler::readHandle,
		shared_from_this(),
		boost::asio::placeholders::error,
		boost::asio::placeholders::bytes_transferred));
}

void LoginConnectionHandler::readHandle(const boost::system::error_code& err, size_t bytes_transferred)
{
	if (err) {
		socket_.close();
		return;
	}
	std::string data{ boost::asio::buffer_cast<const char*>(strBuf->data()) };
	auto status{ LoginParser::getInstance().processCredentials(data) };
	sendResponse(status);
	strBuf.reset(new boost::asio::streambuf);
	mutableBuffer = strBuf->prepare(msgLength);
	socket_.async_read_some(boost::asio::buffer(mutableBuffer), boost::bind(&LoginConnectionHandler::readHandle,
		shared_from_this(),
		boost::asio::placeholders::error,
		boost::asio::placeholders::bytes_transferred));
}

void LoginConnectionHandler::writeHandle(const boost::system::error_code& err, size_t bytes_transferred)
{
	if (err) {
		socket_.close();
		return;
	}
}

std::shared_ptr<LoginConnectionHandler> LoginConnectionHandler::create(boost::asio::io_service& service)
{
	return std::make_shared<LoginConnectionHandler>(service);
}

void LoginConnectionHandler::writeMessage(const std::string& str)
{
	socket_.async_write_some(boost::asio::buffer(str.c_str(), str.size()), boost::bind(&LoginConnectionHandler::writeHandle,
		shared_from_this(),
		boost::asio::placeholders::error,
		boost::asio::placeholders::bytes_transferred));
}

void LoginConnectionHandler::sendResponse(credentialsStatus status)
{
	Json::Value value;
	Json::FastWriter writer;
	value["command"] = "response";
	if (status == credentialsStatus::RIGHT_PASSWORD || status == credentialsStatus::USER_REGISTERED || status == credentialsStatus::RIGHT_TOKEN) {
		value["status"] = "true";
		value["token"] = LoginParser::getInstance().hash;
		writeMessage(writer.write(value));
		return;
	}
	value["status"] = "false";
	writeMessage(writer.write(value));
}
