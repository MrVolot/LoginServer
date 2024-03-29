#pragma once

#define CORRECT 0x0000
#define AUTHSUCCESS 0x0001
#define RIGHTCREDENTIALS 0x0002
#define AUTHFAIL 0x0003
#define WRONGCREDENTIALS 0x0004
#define USERALREADYEXISTS 0x0005
#define GUEST_USER_USER_SUCCESSFUL_LOGIN 0x0006
#define EMAIL_CODE_VERIFICATION 0x0007
#define CORRECT_CODE 0x0008
#define WRONG_CODE 0x0009

static const std::string ContactsTableName{ "Messenger.dbo.CONTACTS" };
static const std::string AuthTableName{ "Messenger.dbo.AUTH" };
static const std::string DbNamePrefix{ "Messenger.dbo." };