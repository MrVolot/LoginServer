#define _CRT_SECURE_NO_WARNINGS

#include "LoginParser.h"
#include "md5/sha256.h"
#include <chrono>
#include <ctime> 
#include <sstream>
#include <iomanip> 
#include <iostream>


LoginParser::LoginParser() = default;

LoginParser& LoginParser::getInstance()
{
	static LoginParser instance{};
	return instance;
}

credentialsStatus LoginParser::processCredentials(const std::string& str)
{
	//TODO
	try {
		reader.parse(str.c_str(), value);
		if (value["command"].asString() == "login") {
			//return Database::getInstance().checkPassword(value["login"].asString(), value["password"].asString());
		}
		if (value["command"].asString() == "register") {
			//return Database::getInstance().registerNewUser(value["login"].asString(), value["password"].asString());
		}
		if (value["command"].asString() == "auth") {
			//return Database::getInstance().authUser(value["login"].asString(), value["token"].asString());
		}
	}catch(Json::LogicError& logicError){
		return credentialsStatus::ERROR_;
	}
}

std::string LoginParser::createHash(const std::string& login, const std::string& password)
{
	SHA256 sha256;
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d%X");
	hash.append(login);
	hash.append(password);
	hash.append(ss.str());
	hash = sha256(hash);
	return hash;
}
