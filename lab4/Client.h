#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <thread>
#include <chrono>

class Client
{
    const char *serverIp; 
    int port; 

    char msgBuf[150000]; 
    std::stringstream ss;

    sockaddr_in serverSockAddr;
    int socketController;

    int bytesRead, bytesWritten;
    struct timeval start1, end1;
    
    addrinfo emptyTCPIPAddrInfo();
    in_addr getInAddrFromAddrinfo(addrinfo* addr);
    void settingIPAndPort(const char* ip, int port);
    addrinfo* createAddrInfofromIP();
    bool setupSocket();
    bool setupSockaddr();
    bool setupSockaddr(const char* ip);
    bool connectSocketToServer();

public:
    // default constructor
    Client();
    bool connectToServer(const char* ip, int port);
    bool connectToServerWithRawIP(const char* ip, int port);
    void recvAppendToSS(int milsec);
    void recvAppendToSSUntilEnoughBytes(int bytes);
    std::string readOneLine();
    void ingnoreLines(int linesCount);
    void clearStreamBuffer();
    void sendToServer(std::string msg);
    void readToString(std::string* str);
    void readMessage();
    void closeConnection();

    

};