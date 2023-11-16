
CC		= gcc
PROGS	= server client
UID		= $(shell stat -c "%u:%g" /build/Makefile 2>/dev/null || stat -c "%u:%g" ./Makefile 2> /dev/null)

all: $(PROGS)

%.o: %.c
	$(CC) -c -g -Wall $<

server: server.o
	$(CC) -o $@ -static $^
	chown -R "$(UID)" *.o $@

client: client.o
	$(CC) -o $@ -static $^
	chown -R "$(UID)" *.o $@

clean:
	rm -f *.o $(PROGS)
