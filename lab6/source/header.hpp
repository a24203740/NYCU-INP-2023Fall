#pragma once
#include <cstdint>
#include <bitset>
#include <unistd.h>

constexpr uint32_t RES_ACK     = 1 << 0;
constexpr uint32_t RES_MALFORM = 1 << 1;
constexpr uint32_t RES_FIN     = 1 << 2;
constexpr uint32_t RES_RST     = 1 << 3;
constexpr uint32_t RES_MAGIC   = 0xDEADBEEF;

// 1 session = 1 file
struct InitMessage {
    uint32_t    filename;
    uint32_t    filesize;
};

struct FileHandler {
    uint32_t    filename;
    size_t      filesize;
    char*       data;
};

struct Session {
    uint16_t    sessionID;
    uint32_t    recievedBytes;
    InitMessage fileMetadata;
    bool        sessionComplete;
};

struct FileDataFragment {
    uint32_t    filename;
    size_t      fragmentSize;
    char*       fragmentStart; // point to start of data, shared with FileHandler
};

constexpr size_t FRAGMENT_SIZE = 1350;
constexpr size_t HEADER_SIZE = sizeof(uint16_t) 
                                + sizeof(uint16_t); 
                                // + sizeof(uint32_t);
struct ClientPacket {
    uint16_t sessionID;
    uint16_t seqNum;
    // uint32_t checksum;
    char     data[FRAGMENT_SIZE];
};

struct ServerStatePacket
{
    uint16_t sessionID;
    std::bitset<1024> bitmap;
};

constexpr size_t INIT_MESSAGE_SIZE = sizeof(InitMessage);
constexpr size_t CLIENT_PACKET_SIZE = sizeof(ClientPacket);
constexpr size_t SERVER_STATE_PACKET_SIZE = sizeof(ServerStatePacket);
