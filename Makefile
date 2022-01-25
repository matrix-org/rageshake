docker: 
	DOCKER_BUILDKIT=1 docker build -t rageshake:latest .
	docker run --rm --name rageshake --network rageshake-search --mount type=bind,source=$(shell pwd)/bugs,target=/bugs --mount type=bind,source=$(shell pwd)/rageshake.yaml,target=/rageshake.yaml -p 127.0.0.1:9110:9110 rageshake:latest -listen :9110

