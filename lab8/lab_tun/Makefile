
SESS	= tunlab
USER	= "$(shell id -u):$(shell id -g)"

all:
	@echo 'Instructions:'
	@echo '  make build     # build required docker image - do it only once'
	@echo '  make tunvpn    # compile your implementation - do it after your code is updated'
	@echo '  make run       # invoke the test runtime environment'

tunvpn:
	make -C ./dist all

build:
	docker build -t chuang/tunlab .

buildenv:
	docker run -it --rm -v "$(PWD):/build" --user $(USER) --workdir=/build chuang/tunlab bash

run: tunvpn
	-@tmux kill-session -t $(SESS) 2>/dev/null && sleep 1
	@if docker network ls | grep $(SESS) >/dev/null 2>&1; then docker network rm $(SESS); fi
	docker network create --attachable --internal --subnet=172.28.28.0/24 --ip-range=172.28.28.0/24 $(SESS)
	-@if [ -f ./tmux.conf -a -d ./dist ]; then tmux start-server \; source-file tmux.conf; else echo "## No tmux.conf and dist found"; fi

run1: tunvpn
	docker run -it --rm -v "$(PWD)/dist:/dist" $(CAP) chuang/tunlab bash

pack: clean
	(cd ..; rm -f lab_tun.tbz; tar -cjf lab_tun.tbz --exclude tunvpn.demo.cpp lab_tun)

clean:
	make -C ./dist clean
	rm -f $(PROGS)
	-docker rmi `docker images | grep '<none>' | awk '{print $$3}'` 2>/dev/null
	-find . -name __pycache__ -exec rm -rf {} \; 2>/dev/null

