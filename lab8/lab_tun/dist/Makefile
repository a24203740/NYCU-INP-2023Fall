
PROGS	= tunvpn
CXX		= g++
CFLAGS	= -Wall
LDFLAGS	=

PWD		= $(shell pwd)
USER	= "$(shell id -u):$(shell id -g)"

all: $(PROGS)

tunvpn: tunvpn.cpp
	docker run -it --rm -v "$(PWD):/build" --user $(USER) --workdir=/build chuang/tunlab $(CXX) -o $@ $(CFLAGS) $^ $(LDFLAGS)

demo: tunvpn.demo.cpp
	docker run -it --rm -v "$(PWD):/build" --user $(USER) --workdir=/build chuang/tunlab $(CXX) -o tunvpn $(CFLAGS) $^ $(LDFLAGS)

clean:
	rm -f *.o $(PROGS)

