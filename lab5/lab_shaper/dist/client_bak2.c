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
#define SIZE 1024*1024*8
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
	int bytes=0, readed=0, notignoreByte=0;
	int ignoreFirstNPacket = 80;
	int packetReceived = 0;
	int desiredPacketReceived = 0;
	struct timeval startTime, curTime;
	double bandwidthInMbps = 0.0;

	double prevDiffTime = 0.0;
	int lastBigDiffBytes = 0;

	while (bytes < size)
	{
		readed = read(sockfd,buffer,size);
		gettimeofday(&curTime, NULL);
		bytes += readed;
		packetReceived++;

		printf("packet # %d\n", packetReceived);
		printf("received packet size = %d bytes\n", readed);
		printf("at time = %ld ms\n", (curTime.tv_sec * 1000 + curTime.tv_usec / 1000) );
		printf("total bytes = %d\n", bytes);
		
		if(packetReceived <= ignoreFirstNPacket)
		{
			continue;
		}
		notignoreByte += readed;
		desiredPacketReceived++;
		if(desiredPacketReceived == 1)
		{
			startTime = curTime;
		}
		else if(desiredPacketReceived == 2)
		{

			//printf("total bytes = %d\n", bytes);
			
			double diffTime = (curTime.tv_sec * 1000.0 + curTime.tv_usec / 1000.0) - (startTime.tv_sec * 1000.0 + startTime.tv_usec / 1000.0); 
			//diffTime -= delay;
			bandwidthInMbps = (double)notignoreByte * 8.0 / (double)(1024*1024) / (diffTime / 1000.0);
			printf("total elpased time is %lf ms\n", diffTime);
			printf("bandwidth = %lf Mbps\n", bandwidthInMbps);
			printf("averaged bandwidth = %lf Mbps\n", bandwidthInMbps);
			//printf("diffTime = %lf, bandwidth = %lf\n", diffTime, bandwidthInMbps);
		}
		else
		{

			//printf("total bytes = %d\n", bytes);

			double diffTime = (curTime.tv_sec * 1000.0 + curTime.tv_usec / 1000.0) - (startTime.tv_sec * 1000.0 + startTime.tv_usec / 1000.0); 
			//diffTime -= delay;
			// caucalate harmonic mean of bandwidth
			double currentBW = (double)notignoreByte * 8.0 / (double)(1024*1024) / (diffTime / 1000.0);
			bandwidthInMbps = (desiredPacketReceived - 1.0) / 
				((desiredPacketReceived - 2.0) / bandwidthInMbps + (1.0 / currentBW));
			printf("total elpased time is %lf ms\n", diffTime);
			if(diffTime - prevDiffTime > 20.0)
			{
				printf("BIG DIFFERENCE OCCUR AT %d with %lf ms and %d KB\n", packetReceived, diffTime - prevDiffTime, (notignoreByte - lastBigDiffBytes) / (1024));
				lastBigDiffBytes = notignoreByte;
			}
			prevDiffTime = diffTime;
			printf("bandwidth = %lf Mbps\n", currentBW);
			printf("averaged bandwidth = %lf Mbps\n", bandwidthInMbps);
			//printf("diffTime = %lf, bandwidth = %lf\n", diffTime, bandwidthInMbps);
		}
		if(readed < 0)
		{
			break;
		}
		printf("====================================\n");
	}
	printf("total bytes = %d\n", bytes);
	printf("total packet = %d\n", desiredPacketReceived + ignoreFirstNPacket);
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
	delayInMs = delayInMs;
	double bandwidthInMbps = readWithSize(sockfd, serv_addr, SIZE, delayInMs);
	// double bandwidthInMbps = 1.0;
	close(sockfd);
	printf("# RESULTS: delay = %lf ms, bandwidth = %lf Mbps\n", delayInMs, bandwidthInMbps);
    return 0;
}