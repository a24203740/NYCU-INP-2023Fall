#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <netinet/in.h>

#define isDebug 0
// #define DEBUG(X) if(isDebug) printf("%s: %s\n", #X, X);
// #define DEBUGInt(X) if(isDebug) printf("%s: %d\n", #X, X);
#define DEBUG(X)
#define DEBUGInt(X) 
#define errquit(m)	{ perror(m); exit(-1); }

static int port_http = 80;
static int port_https = 443;
static const char *docroot = "/html";

void readHTTPrequestHeader(int sock, char** method, char** path) {
	char buf[2048];
	char headers[2048];
	int n, total = 0;

	while((n = read(sock, buf+total, sizeof(buf) - total)) > 0) {
		total += n;
		//write(1, buf, n);
		char *endOfHeaders = strstr(buf, "\r\n\r\n");
		if (endOfHeaders) {
			// The request is fully sent
			int headersLength = endOfHeaders - buf + 4; // +4 to include "\r\n\r\n"
			memcpy(headers, buf, headersLength);
			headers[headersLength] = '\0'; // Null-terminate the headers string
			break;
		}
	}
	char *firstLine = strtok(headers, "\r\n");
	*method = strtok(firstLine, " ");
	*path = strtok(NULL, " "); // strtok(NULL, " ") will return the next token after the first call to strtok
}

void decodePercentEncoding(char* str, char** decodedStr) {
    char* head = malloc(strlen(str) + 1);
	char* out = head;
    char* in = str;
    while (*in) {
        if (*in == '%' && isxdigit(in[1]) && isxdigit(in[2])) {
            char hex[3] = { in[1], in[2], '\0' };
            *out = strtol(hex, NULL, 16);
			out++;
            in += 3;
        } else {
            *out = *in;
			out++;
			in++;
        }
    }
    *out = '\0';
	*decodedStr = malloc(strlen(head) + 1);
	strcpy(*decodedStr, head);
	free(head);
}

void getRootToPath(char* path, char** newPath, int* isDirectory) {
	*newPath = malloc(strlen(path) + strlen(docroot) + 1);
	strcpy(*newPath, docroot);
	strcat(*newPath, path);
	if(path[strlen(path) - 1] == '/') { // if the path ends with a slash, add index.html
		strcat(*newPath, "index.html");
		*isDirectory = 1;
	}
	else
	{
		*isDirectory = 0;
	}
}

void freeRootToPath(char* path) {
	free(path);
}

void getExtension(char* path, char** extension) {
	char *extensionStart = strrchr(path, '.');
	if (extensionStart) {
		*extension = extensionStart + 1;
	} else {
		*extension = NULL;
	}
}

int checkIfFileExists(char* path) {
	if (access(path, F_OK) == 0)
	{
		return 1;
	}
	return 0;
}

int checkIfFileIsDirectory(char* path) {
	struct stat stat_buf;
	if (stat(path, &stat_buf) < 0) {
		perror("stat");
		return 0;
	}
	return S_ISDIR(stat_buf.st_mode);
}

void write301Response(int sock, char* DirectoryPath) {
	char response[1024];
	
	sprintf(response, 
		"HTTP/1.0 301 Moved Permanently\r\n"
		"Content-Length: 0\r\n"
		"Location: %s/\r\n"
		"\r\n", DirectoryPath);

	write(sock, response, strlen(response));

	DEBUG(response);
}

void write404Response(int sock) {
	char *response = 
	"HTTP/1.0 404 Not Found\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 10\r\n"
	"\r\n"
	"404 error\n";
	write(sock, response, strlen(response));

	DEBUG(response);
}

void write403Response(int sock) {
	char *response = 
	"HTTP/1.0 403 Forbidden\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 10\r\n"
	"\r\n"
	"403 error\n";
	write(sock, response, strlen(response));

	DEBUG(response);
}

void write501Response(int sock) {
	char *response = 
	"HTTP/1.0 501 Not Implemented\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 10\r\n"
	"\r\n"
	"501 error\n";
	write(sock, response, strlen(response));

	DEBUG(response);
}

void getContentType(char* path, char** contentType) {
	char *extension;
	getExtension(path, &extension);
	if(extension == NULL) {
		*contentType = "application/octet-stream";
		return;
	}
	if (strcmp(extension, "html") == 0) 
	{
		*contentType = "text/html";
	}
	else if(strcmp(extension, "mp3") == 0)
	{
		*contentType = "audio/mpeg";
	}
	else if(strcmp(extension, "jpg") == 0)
	{
		*contentType = "image/jpeg";
	}
	else if(strcmp(extension, "png") == 0)
	{
		*contentType = "image/png";
	}
	else
	{
		*contentType = "text/plain";
	}
}

int write200Response(int sock, char* path) {
    int filefd = open(path, O_RDONLY);
    if (filefd < 0) {
        perror("open");
        return 0;
    }

    struct stat stat_buf;
    if (fstat(filefd, &stat_buf) < 0) {
        perror("fstat");
        close(filefd);
        return 0;
    }
	char *contentType;
	getContentType(path, &contentType);
    char responseHeader[128];
    sprintf(responseHeader, 
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "\r\n", contentType, stat_buf.st_size);

	DEBUG(responseHeader);

    write(sock, responseHeader, strlen(responseHeader));

    sendfile(sock, filefd, NULL, stat_buf.st_size);

    close(filefd);
	return 1;
}



void responseRequestToClient(int sock, char* method, char* path) {
	if (strcmp(method, "GET") == 0) {
		char* absolutePath;
		int isDirectory = 0;
		getRootToPath(path, &absolutePath, &isDirectory);

		DEBUG(absolutePath);
		
		if (checkIfFileExists(absolutePath) == 0)
		{
			if(isDirectory == 1) {
				write403Response(sock);
				return;
			}
			else
			{
				write404Response(sock);
				return;
			}
		}
		// if the path is a directory, return 301
		// we have modified the getRootToPath function to add index.html 
		// 	to the path if it ends with a slash
		if(checkIfFileIsDirectory(absolutePath) == 1) {
			write301Response(sock, path); // path is the original path, not the absolute path
			return;
		}
		int sendingFileSuccess = write200Response(sock, absolutePath);

		if(sendingFileSuccess == 0) {
			write404Response(sock);
		}
		freeRootToPath(absolutePath);
	} 
	else
	{
		write501Response(sock);
	}
}

int main(int argc, char *argv[]) {
	int s;
	struct sockaddr_in sin;

	if(argc > 1) { port_http  = strtol(argv[1], NULL, 0); }
	if(argc > 2) { if((docroot = strdup(argv[2])) == NULL) errquit("strdup"); }
	if(argc > 3) { port_https = strtol(argv[3], NULL, 0); }

	if((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) errquit("socket");

	do {
		int v = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	} while(0);

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	if(bind(s, (struct sockaddr*) &sin, sizeof(sin)) < 0) errquit("bind");
	if(listen(s, SOMAXCONN) < 0) errquit("listen");

	do {
		int c;
		struct sockaddr_in csin;
		socklen_t csinlen = sizeof(csin);

		if((c = accept(s, (struct sockaddr*) &csin, &csinlen)) < 0) {
			perror("accept");
			continue;
		}
		int bufsize = 1024 * 1024;
		if (setsockopt(c, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
			perror("setsockopt");
			continue;
		}
		char *method, *path;
		readHTTPrequestHeader(c, &method, &path);

		int percentEncode = 0;
		if(strchr(path, '%') != NULL) {
			percentEncode = 1;
			decodePercentEncoding(path, &path);
		}

		char* questionMark = strchr(path, '?');
		if (questionMark != NULL) {
			*questionMark = '\0';  // Ignore all content following '?'
		}

		DEBUG(method);
		DEBUG(path);
		
		responseRequestToClient(c, method, path);

		//printf("=======================\n");
		//fflush(stdout);

		close(c);

		if(percentEncode == 1) {
			free(path);
		}

	} while(1);

	return 0;
}
