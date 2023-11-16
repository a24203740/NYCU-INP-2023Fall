#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 9999
#define SIZE 1024*1024*16
char buffer[SIZE];
int main(int argc, char *argv[]) {

    int sockfd, newsockfd;
    socklen_t clilen;
	memset(buffer, 'x', sizeof(buffer));
	char bufferMessageWrite[256]="KKKK";
	char bufferMessageRead[256];
    struct sockaddr_in serv_addr, cli_addr;

	int opt = 1;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    listen(sockfd,20);
	while (1)
	{		
		clilen = sizeof(cli_addr);
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		read(newsockfd,bufferMessageRead,1);
		write(newsockfd,bufferMessageWrite,1);
		read(newsockfd,bufferMessageRead,1);
		write(newsockfd,bufferMessageWrite,1);
		read(newsockfd,bufferMessageRead,1);
		
		int bytes = 0, written = 0;
		//sending 40MB DATA
		while (bytes < SIZE)
		{
			written = write(newsockfd,buffer,SIZE);
			bytes += written;
			//printf("Bytes written: %d\n", bytes);
			if(written < 0)
			{
				//printf("Error writing to socket\n");
				break;
			}
		}
		//printf("Bytes written: %d\n", bytes);
		read(newsockfd,bufferMessageRead,1);
		
		close(newsockfd);
	}
    close(sockfd);
    return 0; 
}