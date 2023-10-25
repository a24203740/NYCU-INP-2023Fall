#include "Client.h"


Client::Client()
{
    socketController = -1;
    clearStreamBuffer();
}

addrinfo Client::emptyTCPIPAddrInfo()
{
    addrinfo hints;
    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    return hints;
}

in_addr Client::getInAddrFromAddrinfo(addrinfo* addr)
{
    // note that reinterpret_cast is dangerous.
    // it will not check if the cast is valid.
    // https://stackoverflow.com/questions/11684008/how-do-you-cast-sockaddr-structure-to-a-sockaddr-in-c-networking-sockets-ubu

    sockaddr_in *sin = reinterpret_cast<sockaddr_in*>(addr->ai_addr);
    return sin->sin_addr;
}

void Client::settingIPAndPort(const char* ip, int port)
{
    serverIp = ip;
    this->port = port;
}

addrinfo* Client::createAddrInfofromIP()
{
    addrinfo hints = emptyTCPIPAddrInfo();
    addrinfo* result = nullptr;
    int status = getaddrinfo(serverIp, NULL, &hints, &result); // not 0 means error

    if (status != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return nullptr;
    }

    return result;
}

bool Client::setupSocket()
{
    socketController = socket(AF_INET, SOCK_STREAM, 0);
    //int status = fcntl(socketController, F_SETFL, fcntl(socketController, F_GETFL, 0) | O_NONBLOCK);
    if (socketController < 0)
    {
        std::cerr << "Error creating socket!" << std::endl;
        return false;
    }
    return true;
}

bool Client::setupSockaddr()
{
    addrinfo* addressInfo = createAddrInfofromIP();
    if (addressInfo == nullptr)
    {
        std::cerr << "Error resolving IP to addrinfo!" << std::endl;
        return false;
    }

    bzero(&serverSockAddr, sizeof(serverSockAddr)); // set all bytes to 0
    serverSockAddr.sin_family = AF_INET; 
    serverSockAddr.sin_addr = getInAddrFromAddrinfo(addressInfo);
    serverSockAddr.sin_port = htons(port);

    freeaddrinfo(addressInfo);
    return true;
}

bool Client::connectSocketToServer()
{
    int status = connect(socketController, (sockaddr*)&serverSockAddr, sizeof(serverSockAddr));
    if(status < 0)
    {
        std::cerr << "Error connecting to socket!"<< std::endl;
        return false;
    }
    return true;
}

bool Client::connectToServer(const char* ip, int port)
{
    settingIPAndPort(ip, port);
    if (!setupSocket())
    {
        return false;
    }
    if (!setupSockaddr())
    {
        return false;
    }
    if (!connectSocketToServer())
    {
        return false;
    }
    std::cout << "Connected to the server!" << std::endl;
    return true;
}

void Client::clearStreamBuffer()
{
    ss.str("");
    ss.clear();
}

void Client::recvAppendToSS(int milsec)
{
    memset(&msgBuf, 0, sizeof(msgBuf));//clear the buffer

    std::this_thread::sleep_for(std::chrono::milliseconds(milsec));
    int status = recv(socketController, (char*)&msgBuf, sizeof(msgBuf), 0);
    if(status < 0)
    {
        std::cerr << "Error reading stream!"<< std::endl;
    }
    std::cout << "Received: " << status << " bytes" << std::endl;

    ss << std::string(msgBuf);
}

std::string Client::readOneLine()
{
    std::string line="";
    if(ss.good())
    {
        std::getline(ss, line);
    }
    return line;
}

void Client::closeConnection()
{
    close(socketController);
}

void Client::sendToServer(std::string msg)
{
    int status = send(socketController, msg.c_str(), msg.length(), 0);
    if(status < 0)
    {
        std::cerr << "Error sending message!"<< std::endl;
    }
}
void Client::readMessage() {
    recvAppendToSS(200);
    std::cout << ss.str() << std::endl;
}

void Client::ingnoreLines(int linesCount) {
    for(int i = 0; i < linesCount; i++)
    {
        readOneLine();
    }
}

void Client::readToString(std::string* str) {
    ss >> *str;
}

void Client::recvAppendToSSUntilEnoughBytes(int bytes) {
    memset(&msgBuf, 0, sizeof(msgBuf));//clear the buffer
    int bytesCount = 0;
    while (bytesCount < bytes)
    {
        int status = recv(socketController, (char*)&msgBuf + bytesCount, sizeof(msgBuf), 0);
        if(status < 0)
        {
            std::cerr << "Error reading stream!"<< std::endl;
            break;
        }
        bytesCount += status;
    }
    ss << std::string(msgBuf);
}
