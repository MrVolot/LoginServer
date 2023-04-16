#pragma once
#include "json/json.h"
#include "LoginConstants.h"
#include <string>
#include "emailHandler/EmailHandler.h"

class LoginParser {
	Json::Value value;
	Json::Reader reader;
	EmailHandler emailHandler;

	LoginParser();
	std::string createHash(const std::string& login, const std::string& password);
	credentialsStatus login(const std::string& login, const std::string& password, const std::string& deviceId);
	credentialsStatus registration(const std::string& login, const std::string& password, const std::string& deviceId);
	credentialsStatus auth(const std::string& deviceId);
	void createFriendListTable(const std::string& id);
	credentialsStatus createGuestAccount();
	credentialsStatus verifyEmailCode(const std::string& id, const std::string& code);
public:
	std::string hash;
	std::string userEmail;
	static LoginParser& getInstance();
	credentialsStatus processCredentials(const std::string& str);
	std::string getUserId(const std::string& data);
	std::string generateUniqueCode();
};