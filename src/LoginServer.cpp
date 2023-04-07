#include "LoginServer.h"
#include "Database.h"
#include "ConnectionHandlerSsl.h"
#include "Commands.h"
#include <boost/bind.hpp>
#include <thread>
#include <chrono>

LoginServer::LoginServer(boost::asio::io_service& service) : 
	service_{ service },
	acceptor_{ service, ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 10696) },
	ssl_context_{ boost::asio::ssl::context::sslv23 },
	connection_{ nullptr }
{
	DatabaseHandler::getInstance().connectDB("Login_Server", "123");

	ssl_context_.load_verify_file("C:\\Users\\Kiril\\Desktop\\testing\\ca.crt");
	ssl_context_.use_certificate_chain_file("C:\\Users\\Kiril\\Desktop\\testing\\server.crt");
	ssl_context_.use_private_key_file("C:\\Users\\Kiril\\Desktop\\testing\\server.key", boost::asio::ssl::context::pem);
	ssl_context_.set_verify_mode(boost::asio::ssl::verify_peer);
	ssl_context_.set_verify_callback(boost::bind(&LoginServer::custom_verify_callback, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	ssl_context_.set_options(boost::asio::ssl::context::default_workarounds |
		boost::asio::ssl::context::no_sslv2 |
		boost::asio::ssl::context::no_sslv3 |
		boost::asio::ssl::context::single_dh_use);

	startAccept();
}

void LoginServer::handleAccept(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err)
{
	if (!err) {
		std::cout << "Connection accepted." << std::endl;
		connection_->callAsyncHandshake();
	}
	else {
		std::cout << "Accept error: " << err.message() << std::endl;
	}
	startAccept();
}

void LoginServer::startAccept()
{
	connection_ = std::make_shared<HttpsConnectionHandler<LoginServer>>(service_, *this, ssl_context_);
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
	connection->resetStrBuf();
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
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
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

bool LoginServer::custom_verify_callback(bool preverified, boost::asio::ssl::verify_context& ctx) {
	// Get the X509_STORE_CTX object
	X509_STORE_CTX* store_ctx = ctx.native_handle();

	// Get the current certificate and its depth in the chain
	int depth = X509_STORE_CTX_get_error_depth(store_ctx);
	X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);

	// Convert the X509 certificate to a human-readable format
	BIO* bio = BIO_new(BIO_s_mem());
	X509_print(bio, cert);
	BUF_MEM* mem;
	BIO_get_mem_ptr(bio, &mem);
	std::string cert_info(mem->data, mem->length);
	BIO_free(bio);

	std::cout << "Certificate depth: " << depth << std::endl;
	std::cout << "Certificate information: " << std::endl << cert_info << std::endl;

	// Retrieve the subject name from the certificate
	X509_NAME* subject_name = X509_get_subject_name(cert);
	if (subject_name == NULL) {
		std::cout << "Failed to get subject name" << std::endl;
		return false; // Reject the certificate
	}

	// Get the CN (Common Name) from the subject name
	char common_name[256];
	X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name, sizeof(common_name));

	// Check if the CN contains 'qw'
	if (strstr(common_name, "qw") != NULL) {
		return true;
	}
	else {
		return false; // Reject the certificate if 'qw' is not found in the CN
	}

	std::cout << "Preverified: " << preverified << std::endl;
	return preverified;
}
