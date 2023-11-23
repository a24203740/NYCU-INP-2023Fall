
CC		= gcc
PROGS	= server
UID		= $(shell stat -c "%u:%g" /build/Makefile 2>/dev/null || stat -c "%u:%g" ./Makefile 2> /dev/null)

all: server

%.o: %.c
	$(CC) -c -g -Wall $<

server: server.o
	$(CC) -o $@ -static $^
	chown -R "$(UID)" *.o server

clean:
	rm -f *.o $(PROGS)
