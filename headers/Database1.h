#pragma once
#include "LoginConstants.h"
#include <odbc/Connection.h>
#include <odbc/Environment.h>
#include <string>

class Database {
	odbc::ConnectionRef conn;
	odbc::EnvironmentRef env;
	Database();
public:
	static Database& getInstance();
	void connectDB();
	void disconnectDB();
	bool searchUser(const std::string& login);
	credentialsStatus checkPassword(const std::string& login, const std::string& password);
	credentialsStatus registerNewUser(const std::string& login, const std::string& password);
	credentialsStatus authUser(const std::string& login, const std::string& hash);
};