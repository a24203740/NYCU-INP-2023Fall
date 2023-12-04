/*
 * Lab problem set for INP course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
#include <set>
#include <thread>
#include <chrono>

#define fprintf(...) 1;// disable debug output
// #define printf(...) 1;// disable debug output

#include "util.hpp"

char *filePath;
int fileCount = 0;
int port = 0;
char* serverIP = NULL;

int connectToServer() {
	int s;
	struct sockaddr_in serverAddress;

	if((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		errorQuit("socket");
	}

	bzero((void *)&serverAddress, sizeof(serverAddress));
	serverAddress.sin_family 		= AF_INET;
	serverAddress.sin_addr.s_addr 	= inet_addr(serverIP);
	serverAddress.sin_port 			= htons(port);

	if(connect(s, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
		errorQuit("connect");
	}

	return s;
}

void sendClientPacket(int s, uint16_t sessionID, uint16_t seqNum, const void* data, size_t datalen) {
	ClientPacket* pack = (ClientPacket*) malloc(CLIENT_PACKET_SIZE);
	bzero((void *)pack, CLIENT_PACKET_SIZE);
    pack->sessionID = sessionID;
	pack->seqNum = seqNum;
	memcpy(pack->data, data, datalen);
	// pack->checksum = checksum(pack);
    for(int i = 0; i < 1; i++)
        send(s, (void *)pack, CLIENT_PACKET_SIZE, 0);
	std::this_thread::sleep_for(std::chrono::microseconds(625));
	free(pack);
}

ServerStatePacket* receiveServerState(int s) {
	ServerStatePacket* state = (ServerStatePacket*) malloc(sizeof(ServerStatePacket));
	bzero((void *)state, sizeof(ServerStatePacket));
	int readBytes;
	if((readBytes = recv(s, (void *)state, sizeof(ServerStatePacket), 0)) < 0) {
		// fprintf(stderr, "failed packet, expected=%lu, actual=%d\n", sizeof(ServerStatePacket), readBytes);
		state->sessionID = 5124;
		return state;
	}
	if(readBytes != sizeof(ServerStatePacket)) {
		// fprintf(stderr, "not completed packet, expected=%lu, actual=%d\n", sizeof(ServerStatePacket), readBytes);
		state->sessionID = 5124;
		return state;
	}

	return state;
}

FileHandler* openFile(uint32_t filename, bool copyData = true) {
	FileHandler* fileHandler = (FileHandler*) malloc(sizeof(FileHandler));
	bzero((void *)fileHandler, sizeof(FileHandler));

	fileHandler->filename = filename;
	fileHandler->filesize = 0;
	fileHandler->data = NULL;

	char filenameInString[256];
	sprintf(filenameInString, "%s/%06d", filePath, filename);

	FILE* fp = fopen(filenameInString, "rb");
	if(fp == NULL) {
		// fprintf(stderr, "file %d not found\n", filename);
		free(fileHandler);
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	fileHandler->filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if(copyData) {
		fileHandler->data = (char*) malloc(fileHandler->filesize);
		bzero((void *)fileHandler->data, fileHandler->filesize);

		fread(fileHandler->data, fileHandler->filesize, 1, fp);
	} else {
		fileHandler->data = nullptr;
	}

	fclose(fp);
	return fileHandler;
}

void createFileFragments(const FileHandler* fileHandler, std::vector<FileDataFragment>& fileFragments) {
	size_t fragmentCount = caculateFragmentCount(fileHandler->filesize);
	size_t lastFragmentSize = fileHandler->filesize % FRAGMENT_SIZE;
	if(lastFragmentSize == 0)
	{
		lastFragmentSize = FRAGMENT_SIZE;
	}

	fileFragments.clear();
	fileFragments.reserve(fragmentCount);

	for(size_t i = 0; i < fragmentCount; i++) {
		FileDataFragment fileDataFragment;
		fileDataFragment.filename = fileHandler->filename;
		fileDataFragment.fragmentSize = (i == fragmentCount - 1) ? lastFragmentSize : FRAGMENT_SIZE;
		fileDataFragment.fragmentStart = fileHandler->data + i * FRAGMENT_SIZE;
		fileFragments.push_back(fileDataFragment);
	}
}



void sendInitSession(int s, uint16_t sessionID, const InitMessage* filemetadata) {
	sendClientPacket(s, sessionID, 0, (void *)filemetadata, INIT_MESSAGE_SIZE);
}


int main(int argc, char *argv[]) {
	if (argc != 5){
        return -fprintf(stderr, "Usage: %s <path-to-read-files> <total-number-of-files> <port> <server-ip-address>", argv[0]);
	}

	filePath 	= argv[1];
	fileCount 	= atoi(argv[2]);
	port 		= atoi(argv[3]);
	serverIP 	= argv[4];

	setvbufs();
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

	std::vector<FileHandler*> openFiles;
	std::vector<std::vector<FileDataFragment>> fileFragments;
	
	openFiles.reserve(fileCount);
	fileFragments.reserve(fileCount);

	{
		std::vector<InitMessage> initlist;
		std::set<int> sessionNeedToInit;
		// use fstat for acquireing filesize
		for(int i = 0; i < fileCount; i++) {
			// do not copy data, only get metadata
			FileHandler* fileHandler = openFile(i, false); 
			if(fileHandler == NULL) {
				return -1;
			}
			InitMessage initMessage;
			initMessage.filename = fileHandler->filename;
			initMessage.filesize = fileHandler->filesize;
			initlist.push_back(initMessage);
			sessionNeedToInit.insert(i+1);
			freeFileHandler(fileHandler);
		}
		// printf("all file opened, acquired only metadata\n");
		int serverSocket = connectToServer();
		setSocketTimeOut(serverSocket, 200);
		setSocketRecvBuf(serverSocket, 1024*1024);
		while (!sessionNeedToInit.empty())
		{
			// printf("left %lu session need to init\n", sessionNeedToInit.size());
			for (auto sessID = sessionNeedToInit.begin(); sessID != sessionNeedToInit.end(); sessID++) {
				int i = *sessID - 1;				
				sendInitSession(serverSocket, *sessID, &initlist[i]);
			}
			while(true)
			{
				ServerStatePacket* sessionInitState = receiveServerState(serverSocket);
				if(sessionInitState == nullptr) {
					// fprintf(stderr, "malform response recieved\n");
					continue;
				}
				if(sessionInitState->sessionID != 0) {
					// fprintf(stderr, "timeout\n");
					break;
				}
				for(int i = 0; i < 1024; i++)
				{
					if(sessionInitState->bitmap[i])
					{
						if(sessionNeedToInit.find(i+1) != sessionNeedToInit.end())
						{
							sessionNeedToInit.erase(i+1);
						}
					}
				}
				free(sessionInitState);
			}
		}
		close(serverSocket);
		initlist.clear();
		printf("all session init complete\n");
	}

	// open at most 50 files at a time
	int openFileBase = 0;
	int openFileLimit = 250;
	int completeFileCount = 0;

	std::vector<std::set<int>> fragmentsNeedToSend(fileCount+1, std::set<int>());
	
	int serverSocket = connectToServer();
	setSocketRecvBuf(serverSocket, 1024*1024*36);
	setSocketTimeOut(serverSocket, 100);

	while(completeFileCount < fileCount)
	{
		if(openFileLimit > openFileBase)
		{
			// printf("\033[34mopen files from %d to %d\033[0m\n", openFileBase, openFileLimit);
			for(int i = openFileBase; i < openFileLimit; i++) 
			{
				FileHandler* fileHandler = openFile(i);
				if(fileHandler == NULL) {
					return -1;
				}
				openFiles.push_back(fileHandler);
				std::vector<FileDataFragment> fileFragment;
				createFileFragments(fileHandler, fileFragment);
				fileFragments.push_back(fileFragment);
			}

			for (int i = openFileBase; i < openFileLimit; i++) {
				// FileHandler* fileHandler = openFiles[i];
				std::vector<FileDataFragment>& fileFragment = fileFragments[i];
				
				for(size_t j = 0; j < fileFragment.size(); j++) {
					fragmentsNeedToSend[i].insert(j);
				}
			}
		}
		openFileBase = openFileLimit;

		size_t fragmentLeft = 0;
		int packetSent = 0;

		for(int fileIndex = 0; fileIndex < fragmentsNeedToSend.size(); fileIndex++)
		{
			if(fragmentsNeedToSend[fileIndex].empty())
			{
				continue;
			}
			auto& fragsSet = fragmentsNeedToSend[fileIndex];
			fragmentLeft += fragsSet.size();
			int sessionID = fileIndex;
			for (auto frag = fragsSet.begin(); frag != fragsSet.end(); frag++) {
				int fragmentID = *frag;
				FileDataFragment& fileDataFragment = fileFragments[sessionID][fragmentID];
				sendClientPacket(serverSocket, sessionID+1, fragmentID+1, fileDataFragment.fragmentStart, FRAGMENT_SIZE);
				packetSent++;
			}
			if(packetSent > 3000)
			{
				break;
			}
		}
		printf("\033[33msent %d fragment\033[0m\n", packetSent);
		int ACKCount = 0;
		while(true)
		{
			ServerStatePacket* state = receiveServerState(serverSocket);
			if(state == nullptr) {
				// fprintf(stderr, "malform response recieved\n");
				continue;
			}
			if(state->sessionID == 5124) {
				// fprintf(stderr, "timeout\n");
				break;
			}
			int sessionID = state->sessionID - 1;
			if(sessionID < fileFragments.size() && fileFragments[sessionID].empty()) // completed
			{
				continue;
			}
			if(sessionID > fileFragments.size() || sessionID < 0) // invalid sessionID
			{
				continue;
			}
			int fragmentCount = fileFragments[sessionID].size();
			auto& fragsSet = fragmentsNeedToSend[sessionID];
			bool complete = false;
			for(int fragmentID = 0; fragmentID < fragmentCount; fragmentID++)
			{
				if(state->bitmap[fragmentID] && fragsSet.find(fragmentID) != fragsSet.end())
				{
					ACKCount++;
					fragsSet.erase(fragmentID);
					if(fragsSet.empty())
					{
						complete = true;
					}
				}
			}
			if(complete) 
			{
				// printf("\033[32mfile %d complete\033[0m\n", sessionID);
				freeFileHandler(openFiles[sessionID]);
				fileFragments[sessionID].clear();
				completeFileCount++;
				if(openFileLimit < fileCount)
				{
					openFileLimit++;
				}
				if(completeFileCount == fileCount) 
				{
					break;
				}
			}
			free(state);

		}
		printf("received %d ACK\n", ACKCount);
	}
	
	close(serverSocket);

	
}
