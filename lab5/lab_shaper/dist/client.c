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
#define SIZE 1024*1024*16
char buffer[SIZE];
char bufferMessageWrite[256]="KKKK";
char bufferMessageRead[256];

int packetSizeInBytes[1000];
long long int packetArrivedTimeInUs[1000];
int packetCount = 0;

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
	return ((endTime.tv_sec * 1000000 + endTime.tv_usec) - (startTime.tv_sec * 1000000 + startTime.tv_usec));
}

void readWithSize(int sockfd, struct sockaddr_in serv_addr, int size) 
{
	int bytes = 0, readed = 0;
	int packetReceived = 0;
	struct timeval curTime;

	while (bytes < size)
	{
		readed = read(sockfd,buffer,size);
		gettimeofday(&curTime, NULL);
		bytes += readed;
		packetSizeInBytes[packetReceived] = readed;
		packetArrivedTimeInUs[packetReceived] = curTime.tv_sec * 1000000 + curTime.tv_usec;
		packetReceived++;
		if(readed < 0)
		{
			break;
		}
	}
	packetCount = packetReceived;
	write(sockfd,bufferMessageWrite,1);
}

double resolveBandwidth(long long int delayInUs)
{
	long long int packetDelayInUs[1000];
	short isGarbage[1000];
	long long int prevTime = 0;
	int startPacket = 80;
	for(int i = 0; i < packetCount; i++)
	{
		packetDelayInUs[i] = packetArrivedTimeInUs[i] - prevTime;
		prevTime = packetArrivedTimeInUs[i];
	}
	for(int i = 1; i < packetCount; i++)
	{
		long long int packetDelayDiff = packetDelayInUs[i] - packetDelayInUs[i-1];
		if(packetDelayDiff > 500 || packetDelayDiff < -500 || packetSizeInBytes[i] < 65483)
		{
			isGarbage[i] = 1;
		}
		else
		{
			isGarbage[i] = 0;
		}
	}
	// caculate accumulated bandwidth
	double accumulatedBandwidth[1000];
	long long int totalPacketBytes = 0;
	long long int totalPacketDelay = 0;
	double bytesPerUsToMbps = (1024.0 * 1024.0 / 8.0) / 1000000.0;
	for(int i = startPacket; i < packetCount; i++)
	{
		if(isGarbage[i] == 0)
		{
			totalPacketBytes += packetSizeInBytes[i] + 66;
			totalPacketDelay += packetDelayInUs[i];
		}
		accumulatedBandwidth[i] = (double)totalPacketBytes / ((double)totalPacketDelay) / bytesPerUsToMbps;
	}
	// caculate harmonic average bandwidth
	double sumOfBandwidthreciprocal = 0.0;
	long long int goodPacketCount = 0;
	for(int i = startPacket; i < packetCount; i++)
	{
		if(isGarbage[i] == 0)
		{
			sumOfBandwidthreciprocal += 1.0 / accumulatedBandwidth[i];
			goodPacketCount++;
			//printf("average bandwidth: %lf\n", (double)(goodPacketCount) / sumOfBandwidthreciprocal);
		}
	}
	double harmonicAverageBandwidth = (double)goodPacketCount / sumOfBandwidthreciprocal;
	// for(int i = 1; i < packetCount; i++)
	// {
	// 	printf("packet #%d\n", i);
	// 	printf("packet Size: %d\n", packetSizeInBytes[i]);
	// 	printf("packet delay: %lld\n", packetDelayInUs[i]);
	// 	printf("delay compared to previous packet: %lld\n", packetDelayInUs[i] - packetDelayInUs[i-1]);
	// 	printf("\n================\n");
	// }

	return harmonicAverageBandwidth;
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
	
	long long int delayInUs = getDelay(sockfd, serv_addr) / 2;
	readWithSize(sockfd, serv_addr, SIZE);
	close(sockfd);

	double bandwidthInMbps = resolveBandwidth(delayInUs) / (0.9535);
	// round bandwidth to int
	bandwidthInMbps = (int)(bandwidthInMbps + 0.4);
	double delayInMs = (double)delayInUs / 1000.0;
	delayInMs = (int)(delayInMs);

	// black magic
	// bandwidthInMbps = (int)bandwidthInMbps;
	// delayInMs = (int)delayInMs;


	// double bandwidthInMbps = 1.0;
	printf("# RESULTS: delay = %lf ms, bandwidth = %lf Mbps\n", delayInMs, bandwidthInMbps);
    return 0;
}