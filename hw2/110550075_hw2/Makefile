CPPC	= g++
PROGS	= hw2_chat_server

all: clean hw2_chat_server

%.o: %.cpp
	$(CPPC) -c -Wall $<

hw2_chat_server: hw2_chat_server.o ChatRoomManager.o UserManager.o
	$(CPPC) $^ -o $@

clean:
	rm -f *.o $(PROGS)
