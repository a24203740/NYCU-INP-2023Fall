#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <openssl/ssl.h>

#define isDebug 1
#define DEBUG(X) if(isDebug) printf("%s: %s\n", #X, X);
#define DEBUGInt(X) if(isDebug) printf("%s: %d\n", #X, X);
// #define DEBUG(X)
// #define DEBUGInt(X) 
#define errquit(m)	{ perror(m); exit(-1); }

static int port_http = 80;
static int port_https = 443;
static const char *docroot = "/html";

char filebuffer[1024 * 1024 * 7];

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

void readHTTPSrequestHeader(SSL* sock, char** method, char** path) {
	char buf[2048];
	char headers[2048];
	int n, total = 0;

	while((n = SSL_read(sock, buf+total, sizeof(buf) - total)) > 0) {
		total += n;
		write(1, buf, n);
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
	char response[512];
	response[0] = '\0';
	// using strcat as sprintf is not working somehow

	strcat(response, 
		"HTTP/1.0 301 Moved Permanently\r\n"
		"Content-Length: 0\r\n"
		"Location: ");
	strcat(response, DirectoryPath);
	strcat(response, "/\r\n"
		"\r\n");


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

void writeTLS301Response(SSL* ssl, char* DirectoryPath) {
	char response[1024];
	
	sprintf(response, 
		"HTTP/1.0 301 Moved Permanently\r\n"
		"Content-Length: 0\r\n"
		"Location: %s/\r\n"
		"\r\n", DirectoryPath);

	SSL_write(ssl, response, strlen(response));

	DEBUG(response);
}

void writeTLS404Response(SSL* ssl) {
	char *response = 
	"HTTP/1.0 404 Not Found\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 10\r\n"
	"\r\n"
	"404 error\n";
	SSL_write(ssl, response, strlen(response));

	DEBUG(response);
}

void writeTLS403Response(SSL* ssl) {
	char *response = 
	"HTTP/1.0 403 Forbidden\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 10\r\n"
	"\r\n"
	"403 error\n";
	SSL_write(ssl, response, strlen(response));

	DEBUG(response);
}

void writeTLS501Response(SSL* ssl) {
	char *response = 
	"HTTP/1.0 501 Not Implemented\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 10\r\n"
	"\r\n"
	"501 error\n";
	SSL_write(ssl, response, strlen(response));

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
		*contentType = "text/html; charset=utf-8";
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
		*contentType = "text/plain; charset=utf-8";
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

int writeTLS200Response(SSL* ssl, char* path) {
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

	// write file into filebuffer
	read(filefd, filebuffer, stat_buf.st_size);

    close(filefd);

	char *contentType;
	getContentType(path, &contentType);
    char responseHeader[128];
    sprintf(responseHeader, 
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "\r\n", contentType, stat_buf.st_size);

	DEBUG(responseHeader);

    int status = SSL_write(ssl, responseHeader, strlen(responseHeader));
	DEBUGInt(status);
    status = SSL_write(ssl, filebuffer, stat_buf.st_size);
	DEBUGInt(status);
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

void responseTLSRequestToClient(SSL* ssl, char* method, char* path) {
	if (strcmp(method, "GET") == 0) {
		char* absolutePath;
		int isDirectory = 0;
		getRootToPath(path, &absolutePath, &isDirectory);

		DEBUG(absolutePath);
		
		if (checkIfFileExists(absolutePath) == 0)
		{
			if(isDirectory == 1) {
				writeTLS403Response(ssl);
				return;
			}
			else
			{
				writeTLS404Response(ssl);
				return;
			}
		}
		// if the path is a directory, return 301
		// we have modified the getRootToPath function to add index.html 
		// 	to the path if it ends with a slash
		if(checkIfFileIsDirectory(absolutePath) == 1) {
			writeTLS301Response(ssl, path); // path is the original path, not the absolute path
			return;
		}
		int sendingFileSuccess = writeTLS200Response(ssl, absolutePath);

		if(sendingFileSuccess == 0) {
			writeTLS404Response(ssl);
		}
		freeRootToPath(absolutePath);
	} 
	else
	{
		writeTLS501Response(ssl);
	}
}

int createServerSocket(int port) {
	int s;
	struct sockaddr_in sin;
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	if((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) errquit("socket");

	do {
		int v = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	} while(0);

	if(bind(s, (struct sockaddr*) &sin, sizeof(sin)) < 0) errquit("bind");
	if(listen(s, SOMAXCONN) < 0) errquit("listen");

	return s;
}

void setupClientSocket(int sock) {
	int bufsize = 1024 * 1024;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
		perror("setsockopt");
		return;
	}
	int flag = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0) {
		perror("setsockopt TCP_NODELAY");
		return;
	}

	flag = 0;
	if (setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(int)) < 0) {
		perror("setsockopt TCP_QUICKACK");
		return;
	}
}
int acceptClient(int serverSocket) {
	int c;
	struct sockaddr_in csin;
	socklen_t csinlen = sizeof(csin);

	if((c = accept(serverSocket, (struct sockaddr*) &csin, &csinlen)) < 0) {
		perror("accept");
		return -1;
	}
	setupClientSocket(c);
	return c;
}
void parseRequest(char* method, char** path, int percentEncoding)
{
	if(strchr(*path, '%') != NULL) {
		percentEncoding = 1;
		decodePercentEncoding(*path, &(*path));
	}

	char* questionMark = strchr(*path, '?');
	if (questionMark != NULL) {
		*questionMark = '\0';  // Ignore all content following '?'
	}

	DEBUG(method);
	DEBUG(*path);

}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "/cert/server.crt") <= 0) {
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/cert/server.key", SSL_FILETYPE_PEM) <= 0) {
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
	if(argc > 1) { port_http  = strtol(argv[1], NULL, 0); }
	if(argc > 2) { if((docroot = strdup(argv[2])) == NULL) errquit("strdup"); }
	if(argc > 3) { port_https = strtol(argv[3], NULL, 0); }

	SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
	ssl_ctx = create_context();
	configure_server_context(ssl_ctx);
	

	int httpSocket = createServerSocket(port_http);
	int httpsSocket = createServerSocket(port_https);
	fd_set readFdset;
	FD_ZERO(&readFdset);
	FD_SET(httpSocket, &readFdset);
	FD_SET(httpsSocket, &readFdset);

	int maxFd = httpSocket > httpsSocket ? httpSocket : httpsSocket;


	do {
		fd_set readyReadFds = readFdset;
		if(select(maxFd + 1, &readyReadFds, NULL, NULL, NULL) < 0) {
			perror("select");
			continue;
		}

		if(FD_ISSET(httpSocket, &readyReadFds)) {
			int c = acceptClient(httpSocket);
			if(c < 0) {
				continue;
			}
			char *method, *path;
			readHTTPrequestHeader(c, &method, &path);
			int percentEncode = 0;
			parseRequest(method, &path, percentEncode);
			responseRequestToClient(c, method, path);
			printf("=======================\n");
			fflush(stdout);
			close(c);
			if(percentEncode == 1) {
				free(path);
			}
		}

		if(FD_ISSET(httpsSocket, &readyReadFds)) {
			int c = acceptClient(httpsSocket);
			if(c < 0) {
				continue;
			}
			ssl = SSL_new(ssl_ctx);
			SSL_set_fd(ssl, c);
			if (SSL_accept(ssl) <= 0) {
				close(c);
				continue;
			}
			char *method, *path;
			readHTTPSrequestHeader(ssl, &method, &path);
			int percentEncode = 0;
			parseRequest(method, &path, percentEncode);
			fflush(stdout);
			responseTLSRequestToClient(ssl, method, path);
			printf("=======================\n");
			fflush(stdout);
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(c);
			if(percentEncode == 1) {
				free(path);
			}
		}

	} while(1);

	return 0;
}
