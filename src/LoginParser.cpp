#define _CRT_SECURE_NO_WARNINGS

#include "LoginParser.h"
#include "md5/sha256.h"
#include "Database.h"
#include "Commands.h"
#include <chrono>
#include <ctime> 
#include <sstream>
#include <iomanip> 
#include <random>

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
		if (value["command"].asString() == "guestUserLogin") {
			return createGuestAccount();
		}
		if (value["command"].asString() == "emailCodeConfirmation") {
			return verifyEmailCode(value["userId"].asString(), value["verCode"].asString());
		}
	}
	catch (Json::LogicError& logicError) {
		return credentialsStatus::ERROR_;
	}
}

std::string LoginParser::getUserId(const std::string& data)
{
	reader.parse(data.c_str(), value);
	std::string userIdQuery{ "SELECT ID FROM " + ContactsTableName + " WHERE LOGIN = '" + value["login"].asString() + "'" };
	auto userId{ DatabaseHandler::getInstance().executeQuery(userIdQuery) };
	if (userId.empty()) {
		return "";
	}
	return userId[0][0];
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
	std::string query{ "SELECT LOGIN, EMAIL, AUTHENTICATION_ENABLED, ID FROM " + ContactsTableName + " WHERE LOGIN = '" + login + "' AND PASSWORD = '" + password + "'" };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (result.empty()) {
		return credentialsStatus::WRONG_PASSWORD;
	}

	int authTime{ 5 };
	hash = createHash(login, password);
	query = "UPDATE " + ContactsTableName + " SET TOKEN = '" + hash + "' WHERE LOGIN = '" + login + "'";
	DatabaseHandler::getInstance().executeQuery(query);

	std::string userIdQuery{ "SELECT ID FROM " + ContactsTableName + " WHERE LOGIN = '" + login + "'" };
	auto userId{ DatabaseHandler::getInstance().executeQuery(userIdQuery) };
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");

	if (!DatabaseHandler::getInstance().tableExists(DbNamePrefix + "FL_" + result[0][3])) {
		createFriendListTable(result[0][3]);
	}

	query = "UPDATE " + AuthTableName + " SET DEVICEID = '" + deviceId + "', TOKEN = '" + hash + "', SESSIONTIME = '" + std::to_string(authTime) + "', CREATIONDATE = '" + ss.str() + "' WHERE USERID = " + userId[0][0];
	DatabaseHandler::getInstance().executeQuery(query);

	if (result[0][2] == "1") {
		auto authCode{ generateUniqueCode() };
		emailHandler.sendEmail(result[0][1], authCode);
		query = "UPDATE " + ContactsTableName + " SET AUTHENTICATION_CODE = ? WHERE LOGIN = ? ";
		DatabaseHandler::getInstance().executeWithPreparedStatement(query, { authCode, login });
		return credentialsStatus::AUTHENTICATION_IS_NEEDED;
	}
	else {
		return credentialsStatus::RIGHT_PASSWORD;
	}
}

credentialsStatus LoginParser::registration(const std::string& login, const std::string& password, const std::string& deviceId)
{
	std::string query{ "SELECT LOGIN FROM " + ContactsTableName + " WHERE LOGIN = '" + login + "'" };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (!result.empty()) {
		return credentialsStatus::USER_ALREADY_EXISTS;
	}

	hash = createHash(login, password);
	int authTime{ 5 };
	query = "INSERT INTO " + ContactsTableName + " (LOGIN, PASSWORD, TOKEN) VALUES('" + login + "', '" + password + "', '" + hash + "')";
	DatabaseHandler::getInstance().executeQuery(query);

	std::string userIdQuery{ "SELECT ID FROM " + ContactsTableName + " WHERE LOGIN = '" + login + "'" };
	auto userId{ DatabaseHandler::getInstance().executeQuery(userIdQuery) };
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
	query = "INSERT INTO " + AuthTableName + " VALUES('" + userId[0][0] + "','" + deviceId + "','" + hash + "','" + std::to_string(authTime) + "','" + ss.str() + "')";
	DatabaseHandler::getInstance().executeQuery(query);

	createFriendListTable(userId[0][0]);

	return credentialsStatus::SUCCESSFUL_REGISTRATION;
}

credentialsStatus LoginParser::auth(const std::string& deviceId)
{
	std::string query{ "SELECT SESSIONTIME, CREATIONDATE, TOKEN FROM " + AuthTableName + " WHERE DEVICEID = '" + deviceId + "'" };
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

void LoginParser::createFriendListTable(const std::string& id)
{
	std::string tableName{"FL_" + id};
	std::string query{ "CREATE TABLE " + DbNamePrefix + tableName + "(ID int NOT NULL PRIMARY KEY, Name varchar(255) NOT NULL, CONSTRAINT FK_" + tableName + "_Contacts FOREIGN KEY(ID) REFERENCES " + ContactsTableName + "(ID))" }; // TODO make FR key instead of PM key
	DatabaseHandler::getInstance().executeQuery(query);
}

credentialsStatus LoginParser::createGuestAccount()
{
	auto query{ "INSERT INTO " + ContactsTableName + " (LOGIN, TOKEN, GUID) OUTPUT INSERTED.ID VALUES(? , ? , NEWID())" };
	auto guestName{ "Guest_" + generateUniqueCode() };
	hash = createHash("login" + guestName, "password" + guestName);
	auto result{ DatabaseHandler::getInstance().executeWithPreparedStatement(query, { guestName, hash }) };
	result.next();
	auto guestId{ result.get<std::string>(0) };
	createFriendListTable(guestId);
	return credentialsStatus::GUEST_USER_CREATED_SUCCESSFULLY;
}

credentialsStatus LoginParser::verifyEmailCode(const std::string& id, const std::string& code)
{
	std::string query{ "SELECT AUTHENTICATION_CODE, EMAIL FROM " + ContactsTableName+ " WHERE ID = " + id };
	auto result{ DatabaseHandler::getInstance().executeQuery(query) };
	if (!result.empty() && result[0][0] == code) {
		return credentialsStatus::CORRECT_EMAIL_CODE;
	}
	return credentialsStatus::WRONG_EMAIL_CODE;
}

std::string LoginParser::generateUniqueCode() {
	std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int length = 8; // Length of the random string

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dist(0, charset.size() - 1);

	std::string random_string;
	for (int i = 0; i < length; ++i) {
		random_string += charset[dist(gen)];
	}

	return random_string;
}