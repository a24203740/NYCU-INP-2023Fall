#pragma once

#include <cstdlib>
#include <stdio.h>
#include <errno.h>
#include <cstddef>
#include <stdint.h>
#include <sys/socket.h>

#include "header.hpp"

const uint32_t MOD_ADLER = 65521;

inline void errorQuit(const char* s) {
    if (errno) perror(s);
    else fprintf(stderr, "%s, errno is invalid", s);
    exit(-1);
}

inline void setvbufs() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

// inline uint32_t adler32(const void *_data, size_t len)
// /*
//     where data is the location of the data in physical memory and
//     len is the length of the data in bytes
// */
// {
//     auto data = (const uint8_t*)_data;
//     uint32_t a = 1, b = 0;
//     size_t index;

//     // Process each byte of the data in order
//     for (index = 0; index < len; ++index)
//     {
//         a = (a + data[index]) % MOD_ADLER;
//         b = (b + a) % MOD_ADLER;
//     }

//     return (b << 16) | a;
// }

// inline uint32_t checksum(const ClientPacket* pack) {
//     uint32_t value = adler32(pack->data, FRAGMENT_SIZE);
//     return value ^ pack->seqNum ^ pack->sessionID; 
// }

// inline uint32_t checksum(const ResponsePacket* pack) {
//     return pack->responseFlag ^ pack->seqNum ^ pack->sessionID ^ RES_MAGIC;
// }

inline void dumpDataFragPack(const struct ClientPacket* pack) {
    fprintf(stderr, "=================\ndumping DataFragmentPacket\n");
    fprintf(stderr, "[dump] packet sessionID = %d\n", pack->sessionID);
    // fprintf(stderr, "[dump] packet seqNumber = %d, expected checksum=%x, actual checksum=%x\n",
    //     pack->seqNum, pack->checksum, checksum(pack)
    // );
    // dump data as hex
    fprintf(stderr, "[dump] Data: \n");
    for (size_t i = 0; i < FRAGMENT_SIZE; i++) {
        fprintf(stderr, "%02x ", (uint8_t)pack->data[i]);
    }
    fprintf(stderr, "\n=================\n");
}

inline void freeFileHandler(FileHandler* fileHandler) {
    if(fileHandler->data != nullptr)
    {
	    free(fileHandler->data);
    }
	free(fileHandler);
}

inline size_t caculateFragmentCount(size_t filesize) {
    size_t fragmentCount = filesize / FRAGMENT_SIZE;
	size_t lastFragmentSize = filesize % FRAGMENT_SIZE;
	if(lastFragmentSize != 0) 
	{
		fragmentCount++;
	}
    return fragmentCount;
}

inline void setSocketReuse(int sockfd) {
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
        errorQuit("setsockopt(SO_REUSEADDR)");
}

inline void setSocketTimeOut(int sockfd, int ms) {
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        errorQuit("setsockopt(SO_RCVTIMEO)");
}

inline void setSocketRecvBuf(int sockfd, size_t size) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
        errorQuit("setsockopt(SO_RCVBUF)");
}

inline void setSocketSendBuf(int sockfd, size_t size) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
        errorQuit("setsockopt(SO_SNDBUF)");
}

