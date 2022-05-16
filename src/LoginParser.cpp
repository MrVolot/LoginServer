#define _CRT_SECURE_NO_WARNINGS

#include "LoginParser.h"
#include "md5/sha256.h"
#include "Database.h"
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
	try {
		reader.parse(str.c_str(), value);
		if (value["command"].asString() == "login") {
			return login(value["login"].asString(), value["password"].asString());
		}
		if (value["command"].asString() == "register") {
			return registration(value["login"].asString(), value["password"].asString());
		}
		if (value["command"].asString() == "auth") {
			return auth(value["login"].asString(), value["token"].asString());
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

credentialsStatus LoginParser::login(const std::string& login, const std::string& password)
{
	std::string query{ "SELECT LOGIN FROM CONTACTS WHERE LOGIN = '" + login + "' AND PASSWORD = '" + password + "'"};
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (result.empty()) {
		return credentialsStatus::WRONG_PASSWORD;
	}
	auto newHash{ createHash(login, password) };
	hash = newHash;
	query = "UPDATE CONTACTS SET TOKEN = '" + hash + "' WHERE LOGIN = '" + login + "'";
	DatabaseHandler::getInstance().executeQuery(query);
	return credentialsStatus::RIGHT_PASSWORD;
}

credentialsStatus LoginParser::registration(const std::string& login, const std::string& password)
{
	std::string query{ "SELECT LOGIN FROM CONTACTS WHERE LOGIN = '" + login + "'" };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (!result.empty()) {
		return credentialsStatus::USER_ALREADY_EXISTS;
	}
	auto newHash{ createHash(login, password) };
	hash = newHash;
	query = "INSERT INTO CONTACTS VALUES ('" + login + "','" + password + "','" + hash + "')";
	DatabaseHandler::getInstance().executeQuery(query);
	return credentialsStatus::USER_REGISTERED;
}

credentialsStatus LoginParser::auth(const std::string& login, const std::string& token)
{
	std::string query{ "SELECT LOGIN FROM CONTACTS WHERE LOGIN = '" + login + "' AND TOKEN = '" + token + "'" };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (result.empty()) {
		return credentialsStatus::WRONG_TOKEN;
	}
	hash = token;
	return credentialsStatus::RIGHT_TOKEN;
}
