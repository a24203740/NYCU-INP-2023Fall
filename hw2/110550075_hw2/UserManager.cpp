#include "UserManager.h"

bool UserManager::checkUsernameExists(std::string username)
{
    return usernameLookupTable.find(username) != usernameLookupTable.end();
}
bool UserManager::checkPasswordCorrect(std::string username, std::string password)
{
    return usernameLookupTable[username]->password == password;
}
bool UserManager::checkUserIsLogin(int clientFD)
{
    return FDtoLoginUserLookupTable.find(clientFD) != FDtoLoginUserLookupTable.end();
}
bool UserManager::checkUserIsLogin(std::string username)
{
    return usernameLookupTable[username]->isLogin;
}
bool UserManager::checkUserIsChatting(int clientFD)
{
    return FDtoLoginUserLookupTable[clientFD]->isChatting;
}
bool UserManager::checkUserIsChatting(std::string username)
{
    return usernameLookupTable[username]->isChatting;
}

void UserManager::registerNewUser(std::string username, std::string password) 
{
    usernameLookupTable[username] = std::make_shared<User>(username, password);    
}

void UserManager::clientLogin(std::string username, int clientFD) 
{
    auto user = usernameLookupTable[username];
    user->isLogin = true;
    user->loginFD = clientFD;
    user->status = "online";
    FDtoLoginUserLookupTable[clientFD] = user;    
}

void UserManager::clientLogout(int clientFD)
{
    auto user = FDtoLoginUserLookupTable[clientFD];
    user->isLogin = false;
    user->loginFD = -1;
    user->status = "offline";
    FDtoLoginUserLookupTable.erase(clientFD);
}

void UserManager::clientJoinChatRoom(int clientFD, int chatRoomNumber) 
{
    auto user = FDtoLoginUserLookupTable[clientFD];
    user->isChatting = true;
    user->chatRoomNumber = chatRoomNumber;
}

void UserManager::clientLeaveChatRoom(int clientFD) 
{
    auto user = FDtoLoginUserLookupTable[clientFD];
    user->isChatting = false;
    user->chatRoomNumber = -1;
}

std::string UserManager::getUsername(int clientFD) 
{
    return FDtoLoginUserLookupTable[clientFD]->username;
}

std::string UserManager::getStatus(std::string username) 
{
    return usernameLookupTable[username]->status;    
}

std::string UserManager::getStatus(int clientFD) 
{
    return FDtoLoginUserLookupTable[clientFD]->status;
}

int UserManager::getChatRoomNumber(std::string username) 
{
    return usernameLookupTable[username]->chatRoomNumber;
}

int UserManager::getChatRoomNumber(int clientFD) 
{
    return FDtoLoginUserLookupTable[clientFD]->chatRoomNumber;
}

std::vector<std::string> UserManager::getUserList() 
{
    std::vector<std::string> userList;
    for(auto& pair : usernameLookupTable)
    {
        userList.push_back(pair.first);
    }
    return userList;    
}

void UserManager::setUserStatus(int clientFD, std::string status) 
{
    FDtoLoginUserLookupTable[clientFD]->status = status;    
}

void UserManager::setUserStatus(std::string username, std::string status) 
{
    usernameLookupTable[username]->status = status;    
}

