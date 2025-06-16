#!/bin/bash

set -e

# Just in case the container is already running, remove it
docker rm -f rageshake-minio || true

# Start MinIO server (detached)
docker run -d --name rageshake-minio \
  -p 9000:9000 -p 9001:9001 \
  -e "MINIO_ROOT_USER=minioadmin" \
  -e "MINIO_ROOT_PASSWORD=minioadmin" \
  minio/minio server /data --console-address ":9001"

echo "Waiting for MinIO to be ready..."
sleep 5

go build -o rageshake .

echo "Starting rageshake server..."
./rageshake --config rageshake.sample.yaml

docker rm -f rageshake-minio