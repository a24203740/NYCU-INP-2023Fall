/*
 * Lab problem set for INP course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <vector>
#include <map>
#include <bitset>
#include <chrono>

#include "util.hpp"

#define fprintf(...) 1;// disable debug output
// #define printf(...) 1;// disable debug output

char *filePath;
int fileCount = 0;
int port = 0;


void sendServerState(int s, struct sockaddr_in* csin, uint16_t sessionID, std::bitset<512> sessionState)
{
	ServerStatePacket* state = (ServerStatePacket*) malloc(SERVER_STATE_PACKET_SIZE);
	bzero((void *)state, SERVER_STATE_PACKET_SIZE);
	state->sessionID = sessionID;
	state->bitmap = sessionState;
	socklen_t csinlen = sizeof(*csin);

	for(int i = 0; i < 3; i++)
	{
		if(sendto(s, (void *) state, SERVER_STATE_PACKET_SIZE, 0, (struct sockaddr*) csin, csinlen) < 0) {
			errorQuit("sendto");
		}
		// sleep(0.0005); // sleep 0.5ms
	}

	free(state);
}


ClientPacket* receiveFromClient(int s, struct sockaddr_in* csin) {
	ClientPacket* pack = (ClientPacket*) malloc(CLIENT_PACKET_SIZE);
	bzero((void *)pack, CLIENT_PACKET_SIZE);
	socklen_t csinlen = sizeof(*csin);

	int readBytes;
	
	if((readBytes = recvfrom(s,(void *) pack, CLIENT_PACKET_SIZE, 0, (struct sockaddr*) csin, &csinlen)) < 0) {
		errorQuit("recvfrom");
	}
	if(readBytes != CLIENT_PACKET_SIZE) {
		fprintf(stderr, "not completed packet, expected=%lu, actual=%d\n", CLIENT_PACKET_SIZE, readBytes);
		return NULL;
	}

	return pack;

}

int main(int argc, char *argv[]) {

	if(argc != 4) {
		return -fprintf(stderr, "usage: %s <path-to-store-files> <total-number-of-files> <port>\n", argv[0]);
	}

	filePath 	= argv[1];
	fileCount 	= atoi(argv[2]);
	port 		= atoi(argv[3]);

	int s;
	struct sockaddr_in sin;

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	if((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		errorQuit("socket");

	if(bind(s, (struct sockaddr*) &sin, sizeof(sin)) < 0)
		errorQuit("bind");

	setSocketReuse(s);
	setSocketSendBuf(s, 1024*10*SERVER_STATE_PACKET_SIZE);
	setSocketRecvBuf(s, 1024*36*CLIENT_PACKET_SIZE);

	std::map<uint16_t, Session*> sessionsMap;

	std::vector<std::vector<char*>> dataFragmentVector;
	std::vector<std::bitset<512>> sessionStates;
	std::bitset<1024> sessionHasBeenSentPacket;
	std::bitset<1024> sessionHasInit;

	dataFragmentVector.assign(fileCount, std::vector<char*>());
	sessionStates.assign(fileCount, std::bitset<512>());
	
	auto lastSendTime = std::chrono::steady_clock::now();
	while(1) 
	{
		struct sockaddr_in csin;
		socklen_t csinlen = sizeof(csin);
		
		// must free pack after use
		ClientPacket* pack = receiveFromClient(s, &csin);
		if(pack == NULL) {
			continue;
		}
		uint16_t sessionID = pack->sessionID;
		uint16_t seqNum = pack->seqNum;

		// haven't init
		if(sessionHasInit.test(sessionID) == false)
		{
			// create new session
			Session* session = (Session*) malloc(sizeof(Session));
			bzero((void *)session, sizeof(Session));
			
			session->fileMetadata.filename = pack->sessionID;
			session->fileMetadata.filesize = pack->filesize;
			session->sessionID = sessionID;
			session->recievedBytes = 0;
			session->sessionComplete = false;
			sessionsMap[sessionID] = session;

			size_t fragmentCount = caculateFragmentCount(session->fileMetadata.filesize);
			dataFragmentVector[sessionID].assign(fragmentCount, nullptr);
			sessionHasInit.set(sessionID);
		}

		Session* session = sessionsMap[sessionID];
		sessionHasBeenSentPacket.set(sessionID);

		if(session->sessionComplete) 
		{
			fprintf(stderr, "session already complete\n");
		}
		else if(session->recievedBytes < session->fileMetadata.filesize)
		{
			auto& dataFragment = dataFragmentVector[sessionID];
			if(dataFragment[seqNum] == nullptr) {
				dataFragment[seqNum] = (char*) malloc(FRAGMENT_SIZE);
				memcpy(dataFragment[seqNum], pack->data, FRAGMENT_SIZE);
				session->recievedBytes += FRAGMENT_SIZE;
				sessionStates[sessionID].set(seqNum);
			}
			else
			{
				fprintf(stderr, "duplicate packet\n");
			}
		}

		free(pack);

		// session complete
		if(!session->sessionComplete && session->recievedBytes >= session->fileMetadata.filesize) 
		{
			// printf("\033[31m[SERVER]: session %d complete\033[0m\n", sessionID);
			session->sessionComplete = true;
			char filename[256];
			sprintf(filename, "%s/%06d", filePath, session->fileMetadata.filename);
			FILE* file = fopen(filename, "wb");

			auto& dataFragment = dataFragmentVector[sessionID];
			size_t lastFragmentSize = session->fileMetadata.filesize % FRAGMENT_SIZE;
			if(lastFragmentSize == 0)
			{
				lastFragmentSize = FRAGMENT_SIZE;
			}
			for(size_t i = 0; i < dataFragment.size(); i++) {
				if(i == dataFragment.size()-1)
					fwrite(dataFragment[i], sizeof(char), lastFragmentSize, file);
				else
					fwrite(dataFragment[i], sizeof(char), FRAGMENT_SIZE, file);
				free(dataFragment[i]);
			}
			fclose(file);
		}
		{
			auto now = std::chrono::steady_clock::now();
        	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSendTime);
			if (duration.count() >= 100) {

				// send server state
				// printf("\033[31m[SERVER]: send server state\033[0m\n");
				for(int i = 0; i < sessionStates.size(); i++)
				{
					if(!sessionHasBeenSentPacket.test(i))
					{
						continue;
					}
					auto& sessionState = sessionStates[i];
					sendServerState(s, &csin, i, sessionState);
				}
				sessionHasBeenSentPacket.reset();
				lastSendTime = now;
			}
        }
	}

	close(s);
}
