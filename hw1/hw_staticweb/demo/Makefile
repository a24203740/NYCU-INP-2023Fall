CC		= gcc
PROGS	= server server_https
UID		= $(shell stat -c "%u:%g" /build/Makefile 2>/dev/null || stat -c "%u:%g" ./Makefile 2> /dev/null)

all: server

%.o: %.c
	$(CC) -c -g -Wall $<

server: server.o
	$(CC) -o $@ -static $^ -lpthread
	chown -R "$(UID)" *.o server

https: server_https.o
	$(CC) -o server_https -static $^ -lssl -lcrypto -lpthread
	chown -R "$(UID)" *.o server_https

clean:
	rm -f *.o $(PROGS)
