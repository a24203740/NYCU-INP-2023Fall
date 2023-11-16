
all:
	docker exec -ti lab_builder make -C /build clean all

test%:
	docker exec -it lab_shaper /scripts/$@.py

clean:
	make -C dist clean
