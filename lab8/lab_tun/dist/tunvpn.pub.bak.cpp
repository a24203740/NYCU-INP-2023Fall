/*
 *  Lab problem set for INP course
 *  by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 *  License: GPLv2
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <map>
#include <set>
#include <thread>
#include <chrono>

#define NIPQUAD(m)	((unsigned char*) &(m))[0], ((unsigned char*) &(m))[1], ((unsigned char*) &(m))[2], ((unsigned char*) &(m))[3]
#define errquit(m)	{ perror(m); exit(-1); }

#define MYADDR		0x0a0000fe
#define ADDRBASE	0x0a00000a
#define	NETMASK		0xffffff00

int error = 0;
int count = 0;


std::set<int> availableSubIP;
std::map<in_addr_t, int> ipToFD;
std::map<int, in_addr> FDToIP;


void initAvailableIp()
{
	for(int i = 10; i < 254; i++)
	{
		availableSubIP.insert(i);
	}
}

void assignIP(int clientFD)
{
	if(availableSubIP.empty())
	{
		fprintf(stderr, "## [server] no available ip\n");
		exit(-1);
	}
	char ip[16];
	sprintf(ip, "10.0.0.%d", *availableSubIP.begin());
	write(clientFD, &ip, sizeof(ip));
	availableSubIP.erase(availableSubIP.begin());

	in_addr addr;
	addr.s_addr = inet_addr(ip);
	ipToFD[addr.s_addr] = clientFD;
	FDToIP[clientFD] = addr;
}

void releaseIP(int clientFD)
{
	in_addr addr = FDToIP[clientFD];
	availableSubIP.insert(addr.s_addr & 0xff);
	ipToFD.erase(addr.s_addr);
	FDToIP.erase(clientFD);
}

in_addr getAddrFromName(const char* name)
{
	struct addrinfo hints, *res;
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	int err;
	if ((err = getaddrinfo(name, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "## [client] getaddrinfo error: %s\n", gai_strerror(err));
		errquit("getaddrinfo");
	}
	in_addr addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
	freeaddrinfo(res);
	return addr;
}

in_addr getAddrOfInterface(const char* dev)
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(fd < 0) errquit("socket");

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if(ioctl(fd, SIOCGIFADDR, &ifr) < 0) errquit("ioctl");
	close(fd);

	printf("interface %s ip is %u.%u.%u.%u\n", dev, NIPQUAD(reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));
	return reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr)->sin_addr;
}

int setupTCPsocket(int port, in_addr addr, bool isServer)
{
	struct sockaddr_in sin;
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0) errquit("socket");
	{
		int opt = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
		// set recv and send buffer
		int bufSize = 1024 * 1024 * 100;
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize));
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize));
	}
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr = addr;
	if(isServer)
	{
		if(bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) errquit("bind");
		if(listen(fd, 5) < 0) errquit("listen");
		printf("## [server] starts ...\n");
	}
	else
	{
		if(connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) errquit("connect");
		printf("## [client] connected to %s:%d\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
	}
	return fd;
}

void printEveryFieldInPacket(ip header)
{
	printf("=====\n");
	printf("version: %u\n", header.ip_v);
	printf("header length: %u\n", header.ip_hl);
	printf("type of service: %u\n", header.ip_tos);
	printf("total length: %u\n", ntohs(header.ip_len));
	printf("identification: %u\n", ntohs(header.ip_id));
	printf("fragment offset field: %u\n", ntohs(header.ip_off));
	printf("time to live: %u\n", header.ip_ttl);
	printf("protocol: %u\n", header.ip_p);
	printf("checksum: %u\n", ntohs(header.ip_sum));
	printf("source address: %s\n", inet_ntoa(header.ip_src));
	printf("dest address: %s\n", inet_ntoa(header.ip_dst));
	printf("=====\n");
}

void serverProcessPackets(int clientFD, int tunFD) 
{
	in_addr serverTun0Addr;
	serverTun0Addr.s_addr = inet_addr("10.0.0.254");
    while (true) 
	{
		
        char message[3000];
		bzero(message, sizeof(message));
        int nread = read(clientFD, message, sizeof(message));
		count++;
        if (nread == 0) {
            printf("Client disconnected\n");
			releaseIP(clientFD);
            close(clientFD);
            break;
        }
		if(nread < 0)
		{
			perror("[server] read");
			continue;
		}
		// if(hasMarker(message, nread))
		// {
		// 	printf("## [server] received packet with marker\n");
		// 	// process with message
		// 	continue;
		// }
		// else
		ip packetHeader;
		memcpy(&packetHeader, message, 20);
		// printf("\033[32m");
		// printEveryFieldInPacket(packetHeader);
		// printf("\033[0m");
		// printf("## [server] send from %s\n", inet_ntoa(packetHeader.ip_src));
		// printf("## [server] send to %s\n", inet_ntoa(packetHeader.ip_dst));			
		// if(nread < length)
		// {
		// 	printf("## [server] packet length error\n");
		// 	printf("## [server] received %u bytes, but packet length is %u\n", nread, length);
		// 	// nread += read(clientFD, message + nread, sizeof(message) - nread);
		// }
		if(packetHeader.ip_dst.s_addr == serverTun0Addr.s_addr)
		{
			write(tunFD, message, nread);
		}
		else
		{
			if(ipToFD.find(packetHeader.ip_dst.s_addr) == ipToFD.end())
			{
				// printf("\033[31m");
				// printf("## [server] no such client\n");
				// // printf("## [server] requested from %s to %s fail\n", inet_ntoa(packetHeader.ip_src) , inet_ntoa(packetHeader.ip_dst));
				// printEveryFieldInPacket(packetHeader);
				// printf("\033[0m");
				error++;
				printf("error rate: %f\n", (double)error / (double)count);
				continue;
			}
			int routeClientFD = ipToFD[packetHeader.ip_dst.s_addr];
			write(routeClientFD, message, nread);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

    }
}
void clientProcessPackets(int listenFD, int rerouteFD) 
{
    while (true) 
	{
        char message[3000];
		bzero(message, sizeof(message));
        int nread = read(listenFD, message, sizeof(message));
        if (nread == 0) {
            printf("Server disconnected\n");
            close(listenFD);
            break;
        }
		if(nread < 0)
		{
			perror("[client] read");
			continue;
		}
		// if(hasMarker(message, nread))
		// {
		// 	printf("## [client] received packet with marker\n");
		// 	// process with message
		// 	continue;
		// }

		// ip packetHeader;
		// memcpy(&packetHeader, message, 20);
		// unsigned short length = ntohs(packetHeader.ip_len);
		// if(length != nread)
		// {
		// 	printf("## [client] send from %s\n", inet_ntoa(packetHeader.ip_src));
		// 	printf("## [client] send to %s\n", inet_ntoa(packetHeader.ip_dst));
		// 	printf("## [client] packet length error\n");
		// 	printf("## [client] received %u bytes, but packet length is %u\n", nread, length);
		// }
		// printEveryFieldInPacket(packetHeader);
		write(rerouteFD, message, nread);
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int
tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;
	if((fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;	/* IFF_TUN (L3), IFF_TAP (L2), IFF_NO_PI (w/ header) */
	if(dev && dev[0] != '\0') strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		close(fd);
		return err;
	}
	if(dev) strcpy(dev, ifr.ifr_name);
	return fd;
}

int
ifreq_set_mtu(int fd, const char *dev, int mtu) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_mtu = mtu;
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	return ioctl(fd, SIOCSIFMTU, &ifr);
}

int
ifreq_get_flag(int fd, const char *dev, short *flag) {
	int err;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	err = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if(err == 0) {
		*flag = ifr.ifr_flags;
	}
	return err;
}

int
ifreq_set_flag(int fd, const char *dev, short flag) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_flags = flag;
	return ioctl(fd, SIOCSIFFLAGS, &ifr);
}

int
ifreq_set_sockaddr(int fd, const char *dev, int cmd, unsigned int addr) {
	struct ifreq ifr;
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	if(dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	return ioctl(fd, cmd, &ifr);
}

int
ifreq_set_addr(int fd, const char *dev, unsigned int addr) {
	return ifreq_set_sockaddr(fd, dev, SIOCSIFADDR, addr);
}

int
ifreq_set_netmask(int fd, const char *dev, unsigned int addr) {
	return ifreq_set_sockaddr(fd, dev, SIOCSIFNETMASK, addr);
}

int
ifreq_set_broadcast(int fd, const char *dev, unsigned int addr) {
	return ifreq_set_sockaddr(fd, dev, SIOCSIFBRDADDR, addr);
}

int
tunvpn_server(int port) {
	initAvailableIp();
	// XXX: implement your server codes here ...
	fprintf(stderr, "## [server] starts ...\n");
	char dev[] = "tun0";
	int tunFD = tun_alloc(dev);

	// configure tun interface
	{
		//build TCP socket
		int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		// configure tun interface
		ifreq_set_mtu(fd, dev, 1400);
		ifreq_set_addr(fd, dev, htonl(MYADDR));
		ifreq_set_netmask(fd, dev, htonl(NETMASK));
		short flag;
		ifreq_get_flag(fd, dev, &flag);
		ifreq_set_flag(fd, dev, flag | IFF_UP);
	}
	fprintf(stderr, "tun is up...\n");
	std::thread threadForTun0(serverProcessPackets, tunFD, tunFD);
	threadForTun0.detach();

	//build another TCP socket, listen on eth0 interface
	int socketFDforETH0 = setupTCPsocket(port, getAddrOfInterface("eth0"), true);

	do
	{
		int client;
		struct sockaddr_in csin;
		socklen_t csinlen = sizeof(csin);

		if((client = accept(socketFDforETH0, (struct sockaddr*) &csin, &csinlen)) < 0) {
			perror("accept");
			continue;
		}
		fprintf(stderr, "## [server] new client %s:%d\n", inet_ntoa(csin.sin_addr), ntohs(csin.sin_port));
		// assign VPN ip to client
		assignIP(client);
		// create a thread to process packets from client
		std::thread t(serverProcessPackets, client, tunFD);
		t.detach();
	}while(1);
	return 0;
}

int
tunvpn_client(const char *server, int port) {
	// XXX: implement your client codes here ...
	fprintf(stderr, "## [client] starts ...\n");
	//build TCP socket and connect to server
    int serverFD = setupTCPsocket(port, getAddrFromName(server), false);
	char ip[16];
	read(serverFD, &ip, sizeof(ip));
	printf("## [client] assigned ip: %s\n", ip);

	//build tun interface
	char dev[] = "tun0";
	int tunFD = tun_alloc(dev);
	// configure tun interface
	{
		//build TCP socket
		int socketFDForTun = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		// configure tun interface
		ifreq_set_mtu(socketFDForTun, dev, 1400);
		ifreq_set_addr(socketFDForTun, dev, inet_addr(ip));
		ifreq_set_netmask(socketFDForTun, dev, htonl(NETMASK));
		short flag;
		ifreq_get_flag(socketFDForTun, dev, &flag);
		ifreq_set_flag(socketFDForTun, dev, flag | IFF_UP);
	}
	fprintf(stderr, "tun is up...\n");
	std::thread threadForTun0(clientProcessPackets, tunFD, serverFD);
	threadForTun0.detach();
	clientProcessPackets(serverFD, tunFD); // while loop

	return 0;
}

int
usage(const char *progname) {
	fprintf(stderr, "usage: %s {server|client} {options ...}\n"
		"# server mode:\n"
		"	%s server port\n"
		"# client mode:\n"
		"	%s client servername serverport\n",
		progname, progname, progname);
	return -1;
}

int main(int argc, char *argv[]) {
	if(argc < 3) {
		return usage(argv[0]);
	}
	if(strcmp(argv[1], "server") == 0) {
		if(argc < 3) return usage(argv[0]);
		return tunvpn_server(strtol(argv[2], NULL, 0));
	} else if(strcmp(argv[1], "client") == 0) {
		if(argc < 4) return usage(argv[0]);
		return tunvpn_client(argv[2], strtol(argv[3], NULL, 0));
	} else {
		fprintf(stderr , "## unknown mode %s\n", argv[1]);
	}
	return 0;
}
