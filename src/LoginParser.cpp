#define _CRT_SECURE_NO_WARNINGS

#include "LoginParser.h"
#include "md5/sha256.h"
#include "Database.h"
#include <chrono>
#include <ctime> 
#include <sstream>
#include <iomanip> 


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
			return login(value["login"].asString(), value["password"].asString(), value["deviceId"].asString());
		}
		if (value["command"].asString() == "register") {
			return registration(value["login"].asString(), value["password"].asString(), value["deviceId"].asString());
		}
		if (value["command"].asString() == "auth") {
			return auth(value["deviceId"].asString());
		}
	}
	catch (Json::LogicError& logicError) {
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

credentialsStatus LoginParser::login(const std::string& login, const std::string& password, const std::string& deviceId)
{
	std::string query{ "SELECT LOGIN FROM CONTACTS WHERE LOGIN = '" + login + "' AND PASSWORD = '" + password + "'" };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (result.empty()) {
		return credentialsStatus::WRONG_PASSWORD;
	}

	int authTime{ 5 };
	hash = createHash(login, password);
	query = "UPDATE CONTACTS SET TOKEN = '" + hash + "' WHERE LOGIN = '" + login + "'";
	DatabaseHandler::getInstance().executeQuery(query);

	std::string userIdQuery{ "SELECT ID FROM CONTACTS WHERE LOGIN = '" + login + "'" };
	auto userId{ DatabaseHandler::getInstance().executeQuery(userIdQuery) };
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");


	query = "UPDATE AUTH SET USERID = '" + userId[0][0] + "', DEVICEID = '" + deviceId + "', TOKEN = '" + hash + "', SESSIONTIME = '" + std::to_string(authTime) + "', CREATIONDATE = '" + ss.str() + "'";
	DatabaseHandler::getInstance().executeQuery(query);
	return credentialsStatus::RIGHT_PASSWORD;
}

credentialsStatus LoginParser::registration(const std::string& login, const std::string& password, const std::string& deviceId)
{
	std::string query{ "SELECT LOGIN FROM CONTACTS WHERE LOGIN = '" + login + "'" };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (!result.empty()) {
		return credentialsStatus::USER_ALREADY_EXISTS;
	}

	hash = createHash(login, password);
	int authTime{ 5 };
	query = "INSERT INTO CONTACTS VALUES ('" + login + "','" + password + "','" + hash + "')";
	DatabaseHandler::getInstance().executeQuery(query);

	std::string userIdQuery{ "SELECT ID FROM CONTACTS WHERE LOGIN = '" + login + "'" };
	auto userId{ DatabaseHandler::getInstance().executeQuery(userIdQuery) };
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");

	query = "INSERT INTO AUTH VALUES('" + userId[0][0] + "','" + deviceId + "','" + hash + "','" + std::to_string(authTime) + "','" + ss.str() + "')";
	DatabaseHandler::getInstance().executeQuery(query);

	return credentialsStatus::SUCCESSFUL_REGISTRATION;
}

credentialsStatus LoginParser::auth(const std::string& deviceId)
{
	std::string query{ "SELECT SESSIONTIME, CREATIONDATE, TOKEN FROM AUTH WHERE DEVICEID = '" + deviceId + "'" };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (result.empty()) {
		return credentialsStatus::AUTHORIZATION_FAILED;
	}
	hash = result[0][2];

	auto now = std::chrono::system_clock::now();
	std::stringstream ss{ result[0][1] };
	std::chrono::time_point<std::chrono::system_clock> creationDate;
	std::chrono::from_stream(ss, "%Y-%m-%d %H:%M:%S", creationDate);

	auto daysLeft{ std::chrono::duration_cast<std::chrono::days>(now - creationDate) };
	if (daysLeft.count() > std::stoi(result[0][0])) {
		return credentialsStatus::AUTHORIZATION_FAILED;
	}
	return credentialsStatus::AUTHORIZATION_SUCCEEDED;
}
