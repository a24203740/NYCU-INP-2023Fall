#include <iostream>
#include <string>
#include <sstream>

namespace CommandParser
{
    struct Command
    {
        enum Type
        {
            REGISTER,
            LOGIN,
            LOGOUT,
            EXIT,
            WHOAMI,
            SET_STATUS,
            LIST_USER,
            ENTER_CHAT_ROOM,
            LIST_CHAT_ROOM,
            CLOSE_CHAT_ROOM,
            CHAT_PIN,
            CHAT_DELETE_PIN,
            CHAT_EXIT_CHAT_ROOM,
            CHAT_LIST_USER_CHAT,
            CHAT_MESSAGE,
            NOT_A_COMMAND
        };
        Type type;
        std::string username;
        std::string password;
        std::string status;
        std::string chatRoomNumberInString;
        std::string message;
        bool malformed = false;
    };

    int getArgumentCount(std::string inputLine);
    Command parseCommand(std::string inputLine, bool isChat);
    void parseBasicCommand(Command& cmd, std::string commandTypeText, int argCount, std::stringstream& ss);
    void parseChatCommand(Command& cmd, std::string commandTypeText, int argCount, std::stringstream& ss, std::string& message);
    void printCommandInfo(Command cmd);

    int getArgumentCount(std::string inputLine)
    {
        int count = 0;
        bool prevIsSpace = false;
        bool isStart = true;
        for(size_t i = 0; i < inputLine.size(); i++)
        {
            if(inputLine[i] == ' ')
            {
                // ignore multiple spaces
                // ignore spaces at the start
                if(prevIsSpace || isStart)
                {
                    continue;
                }
                prevIsSpace = true;
                count++;
            }
            else if(inputLine[i] == '\n')
            {
                // ignore spaces at the end
                if(prevIsSpace)
                {
                    count--;
                }
                break;
            }
            else
            {
                // non space character
                isStart = false;
                prevIsSpace = false;
            }
        }
        return count;
    }
    Command parseCommand(std::string inputLine, bool isChat)
    {
        int argCount = getArgumentCount(inputLine);
        // std::cout << "argCount: " << argCount << std::endl;
        std::stringstream ss(inputLine);
        std::string commandTypeText;
        ss >> commandTypeText;
        Command cmd;
        if(!isChat)
        {
            parseBasicCommand(cmd, commandTypeText, argCount, ss);
        }
        else
        {
            parseChatCommand(cmd, commandTypeText, argCount, ss, inputLine);
        }
        return cmd;
    }
    void parseBasicCommand(Command& cmd, std::string commandTypeText, int argCount, std::stringstream& ss)
    {
        if(commandTypeText == "register")
        {
            cmd.type = Command::Type::REGISTER;
            if(argCount != 2)
            {
                cmd.malformed = true;
                return;
            }
            ss >> cmd.username >> cmd.password;
        }
        else if(commandTypeText == "login")
        {
            cmd.type = Command::Type::LOGIN;
            if(argCount != 2)
            {
                cmd.malformed = true;
                return;
            }
            ss >> cmd.username >> cmd.password;
        }
        else if(commandTypeText == "logout")
        {
            cmd.type = Command::Type::LOGOUT;
            if(argCount != 0)
            {
                cmd.malformed = true;
                return;
            }
        }
        else if(commandTypeText == "exit")
        {
            cmd.type = Command::Type::EXIT;
            if(argCount != 0)
            {
                cmd.malformed = true;
                return;
            }
        }
        else if(commandTypeText == "whoami")
        {
            cmd.type = Command::Type::WHOAMI;
            if(argCount != 0)
            {
                cmd.malformed = true;
                return;
            }
        }
        else if(commandTypeText == "set-status")
        {
            cmd.type = Command::Type::SET_STATUS;
            if(argCount != 1)
            {
                cmd.malformed = true;
                return;
            }
            ss >> cmd.status;
        }
        else if(commandTypeText == "list-user")
        {
            cmd.type = Command::Type::LIST_USER;
            if(argCount != 0)
            {
                cmd.malformed = true;
                return;
            }
        }
        else if(commandTypeText == "enter-chat-room")
        {
            cmd.type = Command::Type::ENTER_CHAT_ROOM;
            if(argCount != 1)
            {
                cmd.malformed = true;
                return;
            }
            ss >> cmd.chatRoomNumberInString;
        }
        else if(commandTypeText == "list-chat-room")
        {
            cmd.type = Command::Type::LIST_CHAT_ROOM;
            if(argCount != 0)
            {
                cmd.malformed = true;
                return;
            }
        }
        else if(commandTypeText == "close-chat-room")
        {
            cmd.type = Command::Type::CLOSE_CHAT_ROOM;
            if(argCount != 1)
            {
                cmd.malformed = true;
                return;
            }
            ss >> cmd.chatRoomNumberInString;
        }
        else
        {
            cmd.type = Command::Type::NOT_A_COMMAND;
        }
    }
    void parseChatCommand(Command& cmd, std::string commandTypeText, int argCount, std::stringstream& ss, std::string& message)
    {
        if(commandTypeText == "/pin")
        {
            cmd.type = Command::Type::CHAT_PIN;
            if(argCount < 1)
            {
                cmd.malformed = true;
                return;
            }
            // remove the first space
            if(ss.peek() == ' ')
            {
                ss.get();
            }
            std::getline(ss, cmd.message);
        }
        else if(commandTypeText == "/delete-pin")
        {
            cmd.type = Command::Type::CHAT_DELETE_PIN;
        }
        else if(commandTypeText == "/exit-chat-room")
        {
            cmd.type = Command::Type::CHAT_EXIT_CHAT_ROOM;
        }
        else if(commandTypeText == "/list-user")
        {
            cmd.type = Command::Type::CHAT_LIST_USER_CHAT;
        }
        else if(commandTypeText.size() > 0 && commandTypeText[0] == '/')
        {
            cmd.type = Command::Type::NOT_A_COMMAND;
        }
        else
        {
            cmd.type = Command::Type::CHAT_MESSAGE;
            cmd.message = message;
            if(cmd.message.size() > 0 && cmd.message.back() == '\n')
            {
                cmd.message.pop_back();
            }
        }
        
    }
    void printCommandInfo(Command cmd)
    {
        std::cout << "Command Type: ";
        switch(cmd.type)
        {
            case Command::Type::REGISTER:
                std::cout << "REGISTER" << std::endl;
                std::cout << "Username: " << cmd.username << std::endl;
                std::cout << "Password: " << cmd.password << std::endl;
                break;
            case Command::Type::LOGIN:
                std::cout << "LOGIN" << std::endl;
                std::cout << "Username: " << cmd.username << std::endl;
                std::cout << "Password: " << cmd.password << std::endl;
                break;
            case Command::Type::LOGOUT:
                std::cout << "LOGOUT" << std::endl;
                break;
            case Command::Type::EXIT:
                std::cout << "EXIT" << std::endl;
                break;
            case Command::Type::WHOAMI:
                std::cout << "WHOAMI" << std::endl;
                break;
            case Command::Type::SET_STATUS:
                std::cout << "SET_STATUS" << std::endl;
                std::cout << "Status: " << cmd.status << std::endl;
                break;
            case Command::Type::LIST_USER:
                std::cout << "LIST_USER" << std::endl;
                break;
            case Command::Type::ENTER_CHAT_ROOM:
                std::cout << "ENTER_CHAT_ROOM" << std::endl;
                std::cout << "Chat Room Number: " << cmd.chatRoomNumberInString << std::endl;
                break;
            case Command::Type::LIST_CHAT_ROOM:
                std::cout << "LIST_CHAT_ROOM" << std::endl;
                break;
            case Command::Type::CLOSE_CHAT_ROOM:
                std::cout << "CLOSE_CHAT_ROOM" << std::endl;
                std::cout << "Chat Room Number: " << cmd.chatRoomNumberInString << std::endl;
                break;
            case Command::Type::CHAT_PIN:
                std::cout << "CHAT_PIN" << std::endl;
                std::cout << "Message: " << cmd.message << std::endl;
                break;
            case Command::Type::CHAT_DELETE_PIN:
                std::cout << "CHAT_DELETE_PIN" << std::endl;
                break;
            case Command::Type::CHAT_EXIT_CHAT_ROOM:
                std::cout << "CHAT_EXIT_CHAT_ROOM" << std::endl;
                break;
            case Command::Type::CHAT_LIST_USER_CHAT:
                std::cout << "CHAT_LIST_USER_CHAT" << std::endl;
                break;
            case Command::Type::CHAT_MESSAGE:
                std::cout << "CHAT_MESSAGE" << std::endl;
                std::cout << "Message: " << cmd.message << std::endl;
                break;
            case Command::Type::NOT_A_COMMAND:
                std::cout << "NOT_A_COMMAND" << std::endl;
                break;
        }
        if(cmd.malformed)
        {
            std::cout << "Malformed command" << std::endl;
        }
    }
} // namespace name


/*
    Command Format
    Basic: 
        1. register <username> <password>
        2. login <username> <password>
        3. logout
        4. exit
        5. whoami
        6. set-status <status>
            a. <status>: online, offline, busy
        7. list-user
        8. enter-chat-room <number>
        9. list-chat-room
        10. close-chat-room <number>
    Chat:
        1. /pin <message>
        2. /delete-pin
        3. /exit-chat-room
        4. /list-user
        5. <message>
*/