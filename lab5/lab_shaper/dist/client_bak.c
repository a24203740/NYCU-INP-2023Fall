#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9999
#define SIZE 1024*1024*40
char buffer[SIZE];
char bufferMessageWrite[256]="KKKK";
char bufferMessageRead[256];

double getDelay(int sockfd, struct sockaddr_in serv_addr) 
{
	struct timeval startTime, endTime;
	write(sockfd,bufferMessageWrite,1);
	read(sockfd,bufferMessageRead,1);
	gettimeofday(&startTime, NULL);
	write(sockfd,bufferMessageWrite,1);
	read(sockfd,bufferMessageRead,1);
	gettimeofday(&endTime, NULL);
	write(sockfd,bufferMessageWrite,1);
	return ((endTime.tv_sec * 1000.0 + endTime.tv_usec / 1000.0) - (startTime.tv_sec * 1000.0 + startTime.tv_usec / 1000.0));
}

double readWithSize(int sockfd, struct sockaddr_in serv_addr, int size, double delay) 
{
	int bytes=0, readed=0;
	int ignoreFirstNPacket = 10;
	int packetReceived = 0;
	int desiredPacketReceived = 0;
	struct timeval startTime, curTime;
	double bandwidthInMbps = 0.0;
	while (bytes < size)
	{
		readed = read(sockfd,buffer,size);
		bytes += readed;
		if(packetReceived <= ignoreFirstNPacket)
		{
			packetReceived++;
			continue;
		}
		desiredPacketReceived++;
		if(desiredPacketReceived == 1)
		{
			gettimeofday(&startTime, NULL);
		}
		else if(desiredPacketReceived == 2)
		{
			gettimeofday(&curTime, NULL);

			//printf("total bytes = %d\n", bytes);
			
			double diffTime = (curTime.tv_sec * 1000.0 + curTime.tv_usec / 1000.0) - (startTime.tv_sec * 1000.0 + startTime.tv_usec / 1000.0); 
			diffTime -= delay;
			bandwidthInMbps = (double)bytes * 8.0 / (double)(1024*1024) / (diffTime / 1000.0);
			
			//printf("diffTime = %lf, bandwidth = %lf\n", diffTime, bandwidthInMbps);
		}
		else
		{
			gettimeofday(&curTime, NULL);

			//printf("total bytes = %d\n", bytes);

			double diffTime = (curTime.tv_sec * 1000.0 + curTime.tv_usec / 1000.0) - (startTime.tv_sec * 1000.0 + startTime.tv_usec / 1000.0); 
			diffTime -= delay;
			// caucalate harmonic mean of bandwidth
			double currentBW = (double)bytes * 8.0 / (double)(1024*1024) / (diffTime / 1000.0);
			bandwidthInMbps = (desiredPacketReceived - 1.0) / 
				((desiredPacketReceived - 2.0) / bandwidthInMbps + (1.0 / currentBW));
			//printf("diffTime = %lf, bandwidth = %lf\n", diffTime, bandwidthInMbps);
		}
		if(readed < 0)
		{
			break;
		}
	}
	write(sockfd,bufferMessageWrite,1);
	return bandwidthInMbps;

}

int main(int argc, char *argv[]) {

    int sockfd;
    struct sockaddr_in serv_addr;

	memset(buffer, 'x', sizeof(buffer));

	int opt = 1;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(PORT);
	connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
	
	double delayInMs = getDelay(sockfd, serv_addr) / 2.0;
	double bandwidthInMbps = readWithSize(sockfd, serv_addr, SIZE, delayInMs);
	// double bandwidthInMbps = 1.0;
	close(sockfd);
	printf("# RESULTS: delay = %lf ms, bandwidth = %lf Mbps\n", delayInMs, bandwidthInMbps);
    return 0;
}