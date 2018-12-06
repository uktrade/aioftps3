#!/bin/sh

set -e

mkdir -p /root/.minio/certs
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj /CN=selfsigned \
    -keyout /root/.minio/certs/private.key \
    -out /root/.minio/certs/public.crt

openssl genrsa 4096 > /test-data/my-bucket-acme/account.key
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj /CN=selfsigned \
    -keyout /test-data/my-bucket-acme/127.0.0.1.key \
    -out /test-data/my-bucket-acme/127.0.0.1.crt

openssl req -new -sha256 -key /test-data/my-bucket-acme/127.0.0.1.key -subj /CN=some-domain \
	-out /test-data/my-bucket-acme/127.0.0.1.csr

/usr/bin/docker-entrypoint.sh -- "$@"
