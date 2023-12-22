#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>

#include <iostream>
#include <string>
#include <vector>

#include "util.hpp"

int port = 9999;

class FDselector
{
    fd_set listenFDs;
    fd_set availableFDs;
    int fdmax = -1;
    int FDsize = 0;
public:
    FDselector() {
        FD_ZERO(&listenFDs);
    }
    void addFD(int fd) {
        FD_SET(fd, &listenFDs);
        if (fd > fdmax) {
            fdmax = fd;
        }
        FDsize++;
    }
    void removeFD(int fd) {
        FD_CLR(fd, &listenFDs);
        FDsize--;
    }
    int updateAvailableFDs() {
        availableFDs = listenFDs;
        return select(fdmax+1, &availableFDs, NULL, NULL, NULL);
    }
    int getNextAvailableFD(int prev)
    {
        for(int i = prev+1; i < fdmax; i++)
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
    sockaddr_in listenAddr;
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_port = htons(port);
    listenAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int res = bind(serverFD, (sockaddr*)&listenAddr, sizeof(listenAddr));
    quitIfError(res, "bind");
    res = listen(serverFD, 5);
    quitIfError(res, "listen");
    return serverFD;
}

void RunServer(int serverFD)
{
    FDselector fdselector;
    fdselector.addFD(serverFD);
    std::cout << "server started, server FD: " << serverFD << std::endl;
    while (true) {
        // std::cout << "Waiting for clients..." << std::endl;
        fdselector.updateAvailableFDs();
        int fd = fdselector.getNextAvailableFD(-1);
        // std::cout << "get fd: " << fd << std::endl;
        while(fd != -1)
        {
            if (fd == serverFD)
            {
                sockaddr_in clientAddr;
                socklen_t clientAddrLen = sizeof(clientAddr);
                int clientFD = accept(serverFD, (sockaddr*)&clientAddr, &clientAddrLen);
                quitIfError(clientFD, "accept");
                fdselector.addFD(clientFD);
                std::cout << "New client connected: " << clientFD << std::endl;
            }
            else
            {
                char buf[1024];
                int res = recv(fd, buf, sizeof(buf), 0);
                if (res == 0)
                {
                    std::cout << "Client disconnected: " << fd << std::endl;
                    fdselector.removeFD(fd);
                    close(fd);
                }
                else
                {
                    std::cout << "Client " << fd << " sent: " << buf << std::endl;
                }
            }
            fd = fdselector.getNextAvailableFD(fd);
        }
    }
}

int main()
{
    int serverFD = SetupServerSocket();
    RunServer(serverFD);
    return 0;
}