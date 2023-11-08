#include "LoginServer.h"
#include "Database.h"
#include "HttpsConnectionHandler.h"
#include "Commands.h"
#include <boost/bind.hpp>
#include <thread>
#include <chrono>
#include <random>
#include "certificateUtils/certificateUtils.h"

LoginServer::LoginServer(boost::asio::io_service& service) :
	service_{ service },
	acceptor_{ service, ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 10696) },
	ssl_context_{ boost::asio::ssl::context::sslv23 },
	connection_{ nullptr }
{
	DatabaseHandler::getInstance().connectDB("Login_Server", "123");

	std::shared_ptr<EVP_PKEY> private_key = certificateUtils::generate_private_key(2048);
	std::shared_ptr<X509> certificate = certificateUtils::generate_self_signed_certificate("LoginServer", private_key.get(), 365);

	// Load the CA certificate into memory
	std::shared_ptr<X509> ca_cert = certificateUtils::load_ca_certificate();

	X509_STORE* cert_store = SSL_CTX_get_cert_store(ssl_context_.native_handle());
	X509_STORE_add_cert(cert_store, ca_cert.get());

	ssl_context_.use_private_key(boost::asio::const_buffer(certificateUtils::private_key_to_pem(private_key.get()).data(),
		certificateUtils::private_key_to_pem(private_key.get()).size()),
		boost::asio::ssl::context::pem);
	ssl_context_.use_certificate(boost::asio::const_buffer(certificateUtils::certificate_to_pem(certificate.get()).data(),
		certificateUtils::certificate_to_pem(certificate.get()).size()),
		boost::asio::ssl::context::pem);
	ssl_context_.set_verify_mode(boost::asio::ssl::verify_peer);
	ssl_context_.set_verify_callback(
		[](bool preverified, boost::asio::ssl::verify_context& ctx) {
			return certificateUtils::custom_verify_callback(preverified, ctx, "LoginServerClient");
		});
	ssl_context_.set_options(boost::asio::ssl::context::default_workarounds |
		boost::asio::ssl::context::no_sslv2 |
		boost::asio::ssl::context::no_sslv3 |
		boost::asio::ssl::context::single_dh_use);

	startAccept();
}

void LoginServer::handleAccept(std::shared_ptr<IConnectionHandler<LoginServer>> connection, const boost::system::error_code& err)
{
	if (!err) {
		connection_->callAsyncHandshake();
	}
	else {
		std::cout << "Accept error: " << err.message() << std::endl;
	}
	startAccept();
}

void LoginServer::startAccept()
{
	connection_ = std::make_shared<HttpsConnectionHandler<LoginServer, ConnectionHandlerType::LOGIN_SERVER>>(service_, *this, ssl_context_);
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
		value["userNickname"] = LoginParser::getInstance().userNickname;
		connection->callWrite(writer.write(value));
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
		connection->getSocket().close();
		return;
	}
	if (status == credentialsStatus::AUTHORIZATION_SUCCEEDED) {
		value["command"] = AUTHSUCCESS;
		value["status"] = "true";
		value["token"] = LoginParser::getInstance().hash;
		value["userNickname"] = LoginParser::getInstance().userNickname;
		connection->callWrite(writer.write(value));
		connection->getSocket().close();
		return;
	}
	if (status == credentialsStatus::AUTHORIZATION_FAILED) {
		value["command"] = AUTHFAIL;
		value["status"] = "false";
		value["token"] = LoginParser::getInstance().hash;
		value["userNickname"] = LoginParser::getInstance().userNickname;
		connection->callWrite(writer.write(value));
		return;
	}
	if (status == credentialsStatus::USER_ALREADY_EXISTS) {
		value["command"] = USERALREADYEXISTS;
		value["status"] = "false";
		connection->callWrite(writer.write(value));
		return;
	}
	if (status == credentialsStatus::GUEST_USER_CREATED_SUCCESSFULLY) {
		value["command"] = GUEST_USER_USER_SUCCESSFUL_LOGIN;
		value["token"] = LoginParser::getInstance().hash;
		connection->callWrite(writer.write(value));
		connection->getSocket().close();
		return;
	}
	if (status == credentialsStatus::AUTHENTICATION_IS_NEEDED) {
		//send the request to confirm authentication by putting in the authCode in the email
		value["command"] = EMAIL_CODE_VERIFICATION;
		value["token"] = LoginParser::getInstance().hash;
		value["personalId"] = userId;
		connection->callWrite(writer.write(value));
		return;
	}
	if (status == credentialsStatus::CORRECT_EMAIL_CODE) {
		value["command"] = CORRECT_CODE;
		connection->callWrite(writer.write(value));
		connection->getSocket().close();
		return;
	}
	if (status == credentialsStatus::WRONG_EMAIL_CODE) {
		value["command"] = WRONG_CODE;
		connection->callWrite(writer.write(value));
		return;
	}
	value["command"] = WRONGCREDENTIALS;
	value["status"] = "false";
	connection->callWrite(writer.write(value));
}
