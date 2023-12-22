#pragma once

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int connectToUnixSocket
    (int &sockfd, sockaddr_un &serv_addr, const char* socketPath);
