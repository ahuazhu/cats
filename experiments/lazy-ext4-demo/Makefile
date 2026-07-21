IMAGE ?= catdev/lazy-ext4-demo:local

.PHONY: build test demo demo-100g production-demo clean

build:
	docker build -t $(IMAGE) .

test:
	python3 -m unittest -v test_chunkstore.py

demo: build
	docker run --rm --privileged --tmpfs /state:exec,size=4g \
		-e VIRTUAL_SIZE_GB=4 \
		-e CHUNK_SIZE_MB=1 \
		-e FILE_COUNT=10000 \
		$(IMAGE)

demo-100g: build
	docker run --rm --privileged --tmpfs /state:exec,size=6g \
		-e VIRTUAL_SIZE_GB=100 \
		-e CHUNK_SIZE_MB=1 \
		-e FILE_COUNT=100000 \
		$(IMAGE)

production-demo: build
	docker run --rm --privileged --tmpfs /state:exec,size=6g \
		--entrypoint /opt/lazy-ext4-demo/production_demo.sh \
		-e VIRTUAL_SIZE_GB=4 \
		-e CHUNK_SIZE_MB=4 \
		-e FILE_COUNT=10000 \
		$(IMAGE)

clean:
	docker image rm $(IMAGE) 2>/dev/null || true
