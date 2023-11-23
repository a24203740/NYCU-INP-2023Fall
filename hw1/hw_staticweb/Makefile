
all:
	make -C demo all

builder:
	docker exec -ti sw_builder make -C /build clean all

test1:
	docker exec -it sw_tester /testcase/run.sh lighttpd

test2:
	docker exec -it sw_tester /testcase/run.sh demo

clean:
	make -C demo clean
