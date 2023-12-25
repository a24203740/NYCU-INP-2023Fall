#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <strings.h>
#include <string.h>

#include <iostream>
#include <string>
#include <vector>

#include "util.hpp"
#include "CommandParser.cpp"
#include "UserManager.h"
#include "ChatRoomManager.h"

// #define DEBUG
#ifdef DEBUG
const bool debug = true;
#endif
#ifndef DEBUG
const bool debug = false;
#endif

int port = 9999;

class FDselector
{
    fd_set listenFDs;
    fd_set availableFDs;
    int fdMax = -1;
    int FDsize = 0;
public:
    FDselector() {
        FD_ZERO(&listenFDs);
    }
    void addFD(int fd) {
        FD_SET(fd, &listenFDs);
        if (fd > fdMax) {
            fdMax = fd;
        }
        FDsize++;
    }
    void removeFD(int fd) {
        FD_CLR(fd, &listenFDs);
        FDsize--;
    }
    int updateAvailableFDs() {
        availableFDs = listenFDs;
        return select(fdMax+1, &availableFDs, NULL, NULL, NULL);
    }
    int getNextAvailableFD(int prev)
    {
        for(int i = prev+1; i <= fdMax; i++)
        {
            if (FD_ISSET(i, &availableFDs))
            {
                return i;
            }
        }
        return -1;
    }
};

int SetupServerSocket()
{
    int serverFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    quitIfError(serverFD, "socket");
    // set reuse addr and port
    int optval = 1;
    int res = setsockopt(serverFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    quitIfError(res, "setsockopt reuse addr");
    res = setsockopt(serverFD, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    quitIfError(res, "setsockopt reuse port");
    // bind
    sockaddr_in listenAddr;
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_port = htons(port);
    listenAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    res = bind(serverFD, (sockaddr*)&listenAddr, sizeof(listenAddr));
    quitIfError(res, "bind");
    res = listen(serverFD, 5);
    quitIfError(res, "listen");
    return serverFD;
}
void writeMessage(int clientFD, std::string message)
{
    send(clientFD, message.c_str(), message.size(), 0);
}
int convertRoomNumber(std::string roomNumberString)
{
    int res = 0;
    if(roomNumberString.size() == 0)
    {
        return -1;
    }
    if(roomNumberString[0] == '0')
    {
        return -1;
    }
    if(roomNumberString.size() > 3)
    {
        return -1;
    }
    for(size_t i = 0; i < roomNumberString.size(); i++)
    {
        if(roomNumberString[i] < '0' || roomNumberString[i] > '9')
        {
            return -1;
        }
        res = res * 10 + (roomNumberString[i] - '0');
    }
    return res;
}

void writeChatHistoryToClient(const std::deque<messageHistory>& chatHistory, int clientFD)
{
    for(auto& historyLine : chatHistory)
    {
        writeMessage(clientFD, "[" + historyLine.sender + "]: " + historyLine.message + "\n");
    }
}

void broadcastMessageToChatRoom(int ignoreFD, std::string message, const std::set<int>& clientFDset)
{
    for(auto& clientFD : clientFDset)
    {
        if(clientFD != ignoreFD)
        {
            writeMessage(clientFD, message);
        }
    }
}

void filterMessage(std::string& message)
{
    static const std::string filterList[5] = 
    {
        "==",
        "superpie",
        "hello",
        "starburst stream",
        "domain expansion"
    };
    static const std::string replaceList[5] = 
    {
        "**",
        "********",
        "*****",
        "****************",
        "****************"
    };
    std::string lowerCaseMessage = message;
    for(size_t i = 0; i < lowerCaseMessage.size(); i++)
    {
        if(lowerCaseMessage[i] >= 'A' && lowerCaseMessage[i] <= 'Z')
        {
            lowerCaseMessage[i] = lowerCaseMessage[i] - 'A' + 'a';
        }
    }
    //linear search
    for(int i = 0; i < 5; i++)
    {
        size_t pos = lowerCaseMessage.find(filterList[i]);
        while(pos != std::string::npos)
        {
            message.replace(pos, filterList[i].size(), replaceList[i]);
            pos = lowerCaseMessage.find(filterList[i], pos + replaceList[i].size());
        }
    }
}

void processCommand(int clientFD, UserManager& userManager, ChatRoomManager& chatRoomManager, std::string commandText, bool& clientExit)
{
    CommandParser::Command cmd;

    bool isLogin = userManager.checkUserIsLogin(clientFD);
    if(isLogin && userManager.checkUserIsChatting(clientFD))
    {
        cmd = CommandParser::parseCommand(commandText, true);
    }
    else
    {
        cmd = CommandParser::parseCommand(commandText, false);
    }
    if(debug)
    {
        CommandParser::printCommandInfo(cmd);
    }

    if(cmd.type == CommandParser::Command::Type::REGISTER)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: register <username> <password>\n");
            return;
        }
        if(userManager.checkUsernameExists(cmd.username))
        {
            writeMessage(clientFD, "Username is already used.\n");
            return;
        }
        userManager.registerNewUser(cmd.username, cmd.password);
        writeMessage(clientFD, "Register successfully.\n");
    }
    else if(cmd.type == CommandParser::Command::Type::LOGIN)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: login <username> <password>\n");
            return;
        }
        if(userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please logout first.\n");
            return;
        }
        if(!userManager.checkUsernameExists(cmd.username))
        {
            writeMessage(clientFD, "Login failed.\n");
            return;
        }
        if(!userManager.checkPasswordCorrect(cmd.username, cmd.password))
        {
            writeMessage(clientFD, "Login failed.\n");
            return;
        }
        if(userManager.checkUserIsLogin(cmd.username))
        {
            writeMessage(clientFD, "Login failed.\n");
            return;
        }
        userManager.clientLogin(cmd.username, clientFD);
        writeMessage(clientFD, "Welcome, " + cmd.username + ".\n");
    }
    else if(cmd.type == CommandParser::Command::Type::LOGOUT)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: logout\n");
            return;
        }
        if(!userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please login first.\n");
            return;
        }
        writeMessage(clientFD, "Bye, " + userManager.getUsername(clientFD) + ".\n");
        userManager.clientLogout(clientFD);
    }
    else if(cmd.type == CommandParser::Command::Type::EXIT)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: exit\n");
            return;
        }
        if(userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Bye, " + userManager.getUsername(clientFD) + ".\n");
            userManager.clientLogout(clientFD);
        }
        close(clientFD);
        clientExit = true;
    }
    else if(cmd.type == CommandParser::Command::Type::WHOAMI)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: whoami\n");
            return;
        }
        if(!userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please login first.\n");
            return;
        }
        writeMessage(clientFD, userManager.getUsername(clientFD) + "\n");
    }
    else if(cmd.type == CommandParser::Command::Type::SET_STATUS)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: set-status <status>\n");
            return;
        }
        if(!userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please login first.\n");
            return;
        }
        if(cmd.status != "online" && cmd.status != "offline" && cmd.status != "busy")
        {
            writeMessage(clientFD, "set-status failed\n");
            return;
        }
        userManager.setUserStatus(clientFD, cmd.status);
        writeMessage(clientFD, userManager.getUsername(clientFD) + " " + cmd.status + "\n");
    }
    else if(cmd.type == CommandParser::Command::Type::LIST_USER)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: list-user\n");
            return;
        }
        if(!userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please login first.\n");
            return;
        }
        std::vector<std::string> userList = userManager.getUserList();
        std::string message = "";
        for(auto& username : userList)
        {
            message += username + " " + userManager.getStatus(username) + "\n";
        }
        writeMessage(clientFD, message);
    }
    else if(cmd.type == CommandParser::Command::Type::ENTER_CHAT_ROOM)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: enter-chat-room <number>\n");
            return;
        }
        int chatRoomNumber = convertRoomNumber(cmd.chatRoomNumberInString);
        if(chatRoomNumber < 1 || chatRoomNumber > 100)
        {
            writeMessage(clientFD, "Number " + cmd.chatRoomNumberInString + " is not valid.\n");
            return;
        }
        if(!userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please login first.\n");
            return;
        }

        if(!chatRoomManager.checkChatRoomNumberExists(chatRoomNumber))
        {
            chatRoomManager.createNewChatRoom(chatRoomNumber, userManager.getUsername(clientFD));
        }
        chatRoomManager.clientJoinChatRoom(chatRoomNumber, clientFD);
        userManager.clientJoinChatRoom(clientFD, chatRoomNumber);

        // send welcome message to client
        writeMessage(clientFD, "Welcome to the public chat room.\n"
                                "Room number: " + std::to_string(chatRoomNumber) + "\n"
                                "Owner: " + chatRoomManager.getOwnerName(chatRoomNumber) + "\n");
        if(!chatRoomManager.checkChatHistoryIsEmpty(chatRoomNumber))
        {
            writeChatHistoryToClient(chatRoomManager.getChatHistory(chatRoomNumber), clientFD);
        }
        if(chatRoomManager.checkRoomHasPinMessage(chatRoomNumber))
        {
            writeMessage(clientFD, "Pin -> " + chatRoomManager.getPinMessage(chatRoomNumber) + "\n");
        }
        broadcastMessageToChatRoom(clientFD, userManager.getUsername(clientFD) + " had enter the chat room.\n", chatRoomManager.getClientInRoom(chatRoomNumber));
    }
    else if(cmd.type == CommandParser::Command::Type::LIST_CHAT_ROOM)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: list-chat-room\n");
            return;
        }
        if(!userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please login first.\n");
            return;
        }
        std::vector<int> chatRoomList = chatRoomManager.getChatRoomList();
        std::string message = "";
        for(auto& chatRoomNumber : chatRoomList)
        {
            message += chatRoomManager.getOwnerName(chatRoomNumber) + " " + std::to_string(chatRoomNumber) + "\n";
        }
        writeMessage(clientFD, message);
    }
    else if(cmd.type == CommandParser::Command::Type::CLOSE_CHAT_ROOM)
    {
        if(cmd.malformed)
        {
            writeMessage(clientFD, "Usage: close-chat-room <number>\n");
            return;
        }
        if(!userManager.checkUserIsLogin(clientFD))
        {
            writeMessage(clientFD, "Please login first.\n");
            return;
        }
        int chatRoomNumber = convertRoomNumber(cmd.chatRoomNumberInString);
        if(!chatRoomManager.checkChatRoomNumberExists(chatRoomNumber))
        {
            writeMessage(clientFD, "Chat room " + cmd.chatRoomNumberInString + " does not exist.\n");
            return;
        }
        if(chatRoomManager.getOwnerName(chatRoomNumber) != userManager.getUsername(clientFD))
        {
            writeMessage(clientFD, "Only the owner can close this chat room.\n");
            return;
        }
        // log out all clients in this chat room
        auto clientList = chatRoomManager.getClientInRoom(chatRoomNumber);
        for(auto& client : clientList)
        {
            writeMessage(client, "Chat room " + std::to_string(chatRoomNumber) + " was closed.\n");
            userManager.clientLeaveChatRoom(client);
            chatRoomManager.clientLeaveChatRoom(chatRoomNumber, client); // not necessary, but for extensibility
            writeMessage(client, "% ");
        }
        chatRoomManager.deleteChatRoom(chatRoomNumber);
        writeMessage(clientFD, "Chat room " + std::to_string(chatRoomNumber) + " was closed.\n");
    }
    else if(cmd.type == CommandParser::Command::Type::CHAT_PIN)
    {
        if(cmd.malformed)
        {
            cmd.message = "";
        }
        int chatRoomNumber = userManager.getChatRoomNumber(clientFD);
        filterMessage(cmd.message);
        chatRoomManager.pinMessage(chatRoomNumber, "[" + userManager.getUsername(clientFD) + "]: " + cmd.message);
        broadcastMessageToChatRoom(-1, "Pin -> " + chatRoomManager.getPinMessage(chatRoomNumber) + "\n", chatRoomManager.getClientInRoom(chatRoomNumber));
    }
    else if(cmd.type == CommandParser::Command::Type::CHAT_DELETE_PIN)
    {
        int chatRoomNumber = userManager.getChatRoomNumber(clientFD);
        if(chatRoomManager.checkRoomHasPinMessage(chatRoomNumber))
        {
            chatRoomManager.deletePinMessage(chatRoomNumber);
        }
        else
        {
            writeMessage(clientFD, "No pin message in chat room " + std::to_string(chatRoomNumber) + "\n");
        }
    }
    else if(cmd.type == CommandParser::Command::Type::CHAT_EXIT_CHAT_ROOM)
    {
        int chatRoomNumber = userManager.getChatRoomNumber(clientFD);
        chatRoomManager.clientLeaveChatRoom(chatRoomNumber, clientFD);
        userManager.clientLeaveChatRoom(clientFD);
        broadcastMessageToChatRoom(clientFD, userManager.getUsername(clientFD) + " had left the chat room.\n", chatRoomManager.getClientInRoom(chatRoomNumber));
    }
    else if(cmd.type == CommandParser::Command::Type::CHAT_LIST_USER_CHAT)
    {
        int chatRoomNumber = userManager.getChatRoomNumber(clientFD);
        auto clientList = chatRoomManager.getClientInRoom(chatRoomNumber);
        std::string message = "";
        for(auto& client : clientList)
        {
            message += userManager.getUsername(client) + " " + userManager.getStatus(client) + "\n";
        }
        writeMessage(clientFD, message);
    }
    else if(cmd.type == CommandParser::Command::Type::CHAT_MESSAGE)
    {
        int chatRoomNumber = userManager.getChatRoomNumber(clientFD);
        filterMessage(cmd.message);
        chatRoomManager.addMessageToChatHistory(chatRoomNumber, userManager.getUsername(clientFD), cmd.message);
        std::string message = "[" + userManager.getUsername(clientFD) + "]: " + cmd.message + "\n";
        broadcastMessageToChatRoom(-1, message, chatRoomManager.getClientInRoom(chatRoomNumber));
    }
    else
    {
        writeMessage(clientFD, "Error: Unknown command\n");
    }
}
void RunServer(int serverFD)
{
    std::string welcomeMessage =    "*********************************\n"
                                    "** Welcome to the Chat server. **\n"
                                    "*********************************\n";

    std::string promptMessage = "% ";

    UserManager userManager;
    ChatRoomManager chatRoomManager;
    FDselector fdSelector;
    fdSelector.addFD(serverFD);
    if(debug) std::cout << "server started, server FD: " << serverFD << std::endl;
    while (true) {
        // std::cout << "Waiting for clients..." << std::endl;
        fdSelector.updateAvailableFDs();
        int fd = fdSelector.getNextAvailableFD(-1);
        // std::cout << "get fd: " << fd << std::endl;
        while(fd != -1)
        {
            if (fd == serverFD)
            {
                sockaddr_in clientAddr;
                socklen_t clientAddrLen = sizeof(clientAddr);
                int clientFD = accept(serverFD, (sockaddr*)&clientAddr, &clientAddrLen);
                quitIfError(clientFD, "accept");
                fdSelector.addFD(clientFD);
                if(debug) std::cout << "New client connected: " << clientFD << std::endl;
                writeMessage(clientFD, welcomeMessage);
                writeMessage(clientFD, promptMessage);
            }
            else
            {
                char buf[1024];
                bzero(buf, sizeof(buf));
                int res = read(fd, buf, sizeof(buf));
                if (res == 0)
                {
                    if(debug) std::cout << "Client disconnected: " << fd << std::endl;
                    if(userManager.checkUserIsLogin(fd))
                    {
                        if(userManager.checkUserIsChatting(fd))
                        {
                            int chatRoomNumber = userManager.getChatRoomNumber(fd);
                            chatRoomManager.clientLeaveChatRoom(chatRoomNumber, fd);
                            userManager.clientLeaveChatRoom(fd);
                            broadcastMessageToChatRoom(fd, userManager.getUsername(fd) + " had left the chat room.\n", chatRoomManager.getClientInRoom(chatRoomNumber));   
                        }
                        userManager.clientLogout(fd);
                    }
                    fdSelector.removeFD(fd);
                    close(fd);
                }
                else
                {
                    if(debug) std::cout << "Client " << fd << " sent: " << buf << std::endl;
                    bool clientExit = false;
                    processCommand(fd, userManager, chatRoomManager, buf, clientExit);
                    if(clientExit)
                    {
                        fdSelector.removeFD(fd);
                    }
                    else if(!userManager.checkUserIsLogin(fd) || !userManager.checkUserIsChatting(fd))
                    {
                        writeMessage(fd, promptMessage);
                    }
                }
            }
            fd = fdSelector.getNextAvailableFD(fd);
        }
    }
}

int main(int argc, char** argv)
{
    if(argc > 1)
    {
        port = atoi(argv[1]);
    }
    int serverFD = SetupServerSocket();
    RunServer(serverFD);
    return 0;
}