#include "Database1.h"
#include "LoginParser.h"
#include <odbc/PreparedStatement.h>
#include <odbc/ResultSet.h>
#include <odbc/Exception.h>
#include <fstream>
#include <iostream>

Database::Database() = default;

Database& Database::getInstance()
{
	static Database instance{};
	return instance;
}

void Database::connectDB()
{
	env = odbc::Environment::create();
	conn = env->createConnection();
	try {
		conn->connect("SQLDB", "Login_Server", "123");
	conn->setAutoCommit(false);
	odbc::PreparedStatementRef psInsert = conn->prepareStatement("USE Messenger");
	psInsert->executeQuery();
	}
	catch (odbc::Exception ex) {
		std::cout << ex.what();
	}
}

void Database::disconnectDB()
{
	conn->disconnect();
}

bool Database::searchUser(const std::string& login)
{
	if (login.empty()) {
		return false;
	}
	std::string sql{ "SELECT * FROM CONTACTS WHERE LOGIN = '" + login + "'" };
	odbc::PreparedStatementRef psSelect{ conn->prepareStatement(sql.c_str()) };
	odbc::ResultSetRef rs = psSelect->executeQuery();
	return rs->next();
}

credentialsStatus Database::checkPassword(const std::string& login, const std::string& password)
{
	if (password.empty()) {
		return credentialsStatus::ERROR_;
	}
	std::string sql{ "SELECT LOGIN,PASSWORD FROM CONTACTS WHERE LOGIN = '" + login + "' AND PASSWORD = '" + password + "'" };
	try {
		odbc::PreparedStatementRef psSelect{ conn->prepareStatement(sql.c_str()) };
		odbc::ResultSetRef rs = psSelect->executeQuery();
		if (rs->next()) {
			conn->commit();
			auto hashValue{ LoginParser::getInstance().createHash(login, password) };
			std::string dbHash{ "UPDATE CONTACTS SET TOKEN = ? WHERE LOGIN = CONVERT(VARCHAR, ?)" };
			try {
				odbc::PreparedStatementRef psSelect2 = conn->prepareStatement(dbHash.c_str());
				psSelect2->setString(1, hashValue);
				psSelect2->setCString(2, login.c_str());
				psSelect2->addBatch();
				psSelect2->executeBatch();
				conn->commit();
			}
			catch (odbc::Exception ex) {
				std::cout << ex.what();
			}
			return credentialsStatus::RIGHT_PASSWORD;
		}
	}
	catch (odbc::Exception ex) {
		std::cout << ex.what();
	}
	return credentialsStatus::WRONG_PASSWORD;
}

credentialsStatus Database::registerNewUser(const std::string& login, const std::string& password)
{
	if (login.empty() || password.empty()) {
		return credentialsStatus::ERROR_;
	}
	if (searchUser(login)) {
		return credentialsStatus::USER_ALREADY_EXISTS;
	}
	auto hashValue{ LoginParser::getInstance().createHash(login, password) };
	std::string sql{ "INSERT INTO CONTACTS (LOGIN, PASSWORD, TOKEN) VALUES(?, ?, ?)" };
	odbc::PreparedStatementRef psInsert{ conn->prepareStatement(sql.c_str()) };
	psInsert->setCString(1, login.c_str());
	psInsert->setCString(2, password.c_str());
	psInsert->setCString(3, hashValue.c_str());
	psInsert->addBatch();
	psInsert->executeBatch();
	conn->commit();
	return credentialsStatus::USER_REGISTERED;
}

credentialsStatus Database::authUser(const std::string& login, const std::string& hash)
{
	if (login.empty() || hash.empty()) {
		return credentialsStatus::ERROR_;
	}
	std::string sql{ "SELECT TOKEN FROM CONTACTS WHERE LOGIN = '" + login + "'" };
	std::string value;
	try {
		odbc::PreparedStatementRef psSelect{ conn->prepareStatement(sql.c_str()) };
		odbc::ResultSetRef rs = psSelect->executeQuery();
		if (rs->next()) {
			value = rs->getString(1)->c_str();
		}
	}
	catch (odbc::Exception ex) {
		std::cout << ex.what();
	}
	if (value == hash) {
		LoginParser::getInstance().hash = hash;
		return credentialsStatus::RIGHT_TOKEN;
	}
	return credentialsStatus::WRONG_TOKEN;
}
