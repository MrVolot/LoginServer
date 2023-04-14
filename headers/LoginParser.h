#pragma once
#include "json/json.h"
#include "LoginConstants.h"
#include <string>

class LoginParser {
	Json::Value value;
	Json::Reader reader;
	LoginParser();
	std::string createHash(const std::string& login, const std::string& password);
	credentialsStatus login(const std::string& login, const std::string& password, const std::string& deviceId);
	credentialsStatus registration(const std::string& login, const std::string& password, const std::string& deviceId);
	credentialsStatus auth(const std::string& deviceId);
	void createFriendListTable(const std::string& id);
	std::string generate_guest_username();
	credentialsStatus createGuestAccount();
public:
	std::string hash;
	static LoginParser& getInstance();
	credentialsStatus processCredentials(const std::string& str);
	std::string getUserId(const std::string& data);
};