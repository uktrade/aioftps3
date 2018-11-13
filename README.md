# aioftps3 [![CircleCI](https://circleci.com/gh/uktrade/aioftps3.svg?style=svg)](https://circleci.com/gh/uktrade/aioftps3) [![Maintainability](https://api.codeclimate.com/v1/badges/4a9332f4782f6b4bf35a/maintainability)](https://codeclimate.com/github/uktrade/aioftps3/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/4a9332f4782f6b4bf35a/test_coverage)](https://codeclimate.com/github/uktrade/aioftps3/test_coverage)

FTP in front of AWS S3, using [asyncio](https://docs.python.org/3/library/asyncio.html), and [aiohttp](https://github.com/aio-libs/aiohttp). Only a subset of the FTP protocol is supported, with implicit TLS and PASV mode; connections will fail otherwise.

## Installation

```bash
pip install aioftps3
```

An SSL key and certificate must be present `$HOME/ssl.key` and `$HOME/ssl.crt` respectively. To create a self-signed certificate, you can use openssl.

```bash
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj /CN=selfsigned \
    -keyout $HOME/ssl.key \
    -out $HOME/ssl.crt
```

## Running

```bash
python -m aioftps3.server_main
```

## Configuration

Configuration is through environment variables

| Varaiable | Description | Example |
| --- | --- | --- |
| `AWS_AUTH_MECHANISM` | How requests to AWS are authenticated. Can be `secret_access_key` or `ecs_role`. If `ecs_role` it is expected that the server runs in an ECS container. | `secret_access_key` |
| `AWS_ACCESS_KEY_ID` | The ID of the  AWS access key, if `AWS_AUTH_MECHANISM` is `secret_access_key`. | _ommitted_ |
| `AWS_SECRET_ACCESS_KEY` | The secret part of the  AWS access key, if `AWS_AUTH_MECHANISM` is `secret_access_key` | _ommitted_ |
| `AWS_S3_BUCKET_REGION` | The region of the S3 bucket that stores the files. | `eu-west-1` |
| `AWS_S3_BUCKET_HOST` | The hostname used to communicate with S3. | `s3-eu-west-1.amazonaws.com` |
| `AWS_S3_BUCKET_NAME` | The name of the bucket files are stored in. | `my-bucket-name` |
| `AWS_S3_BUCKET_DIR_SUFFIX` | The suffix of the keys created in order to simulate a directory. Must start with a forward slash, but does not need to be longer.  | `/` |
| `FTP_USERS__i__LOGIN` | For `i` any integer, the username of an FTP user that can login. | `my-user` |
| `FTP_USERS__i__PASSWORD` | For `i` any integer, the password of an FTP user that can login. | `my-password` |
| `FTP_COMMAND_PORT` | The port that the server listens on for command connections. | `8021` |
| `FTP_DATA_PORTS_FIRST` | The first data port in the range for PASV mode data transfers. | `4001` |
| `FTP_DATA_PORTS_COUNT` | The number of ports used after `FTP_DATA_PORTS_FIRST`. | `30` |
| `FTP_DATA_CIDR_TO_DOMAINS__i__CIDR` | For `i` any integer, a CIDR range used to match the IP of incoming command connections. If a match is found, the IP of the corresponding domain or IP address in `FTP_DATA_CIDR_TO_DOMAINS__i__DOMAIN` is returned to the client in response to PASV mode requests. Some clients will respond to `FTP_DATA_CIDR_TO_DOMAINS__i__DOMAIN` being `0.0.0.0` by making PASV mode data connections to the same IP as the original command connection, but not all. | `0.0.0.0/0` |
| `FTP_DATA_CIDR_TO_DOMAINS__i__DOMAIN` | See `FTP_DATA_CIDR_TO_DOMAINS__i__CIDR`. | `ftp.my-domain.com` |
| `HEALTHCHECK_PORT` | The port the server listens on for healthcheck requests, such as from an AWS network load balancer. | `8022` |


## Running tests

Certificates must be created, and Minio, which emulates S3 locally, must be started

```bash
./certificates-create.sh && ./minio-start.sh
```

and then to run the tests themselves.

```bash
./tests.sh
```


## Features / Design / Limitations

- Can upload files bigger than 2G: uses [multipart upload](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingRESTAPImpUpload.html) under the hood.

- Does not store uploading files in memory before uploading them to S3: i.e. it is effectively a streaming upload. However, it's not completely streaming: each part of multipart upload is stored in memory before it begins to transfer to S3, in order to be able to hash its content and determine its length.

- For uploading files, hashes are computed incrementally as data comes in in order to not block the event loop just before uploads to S3.

- As few dependencies as is reasonable: aiohttp and its dependencies. Boto 3 is _not_ used.

- May not behave well if upload to the server is faster than its upload to S3.

- There is some locking to deal with the same files being operated on concurrently. However...

- .... it does nothing to deal with [eventual consistency of S3](https://docs.aws.amazon.com/AmazonS3/latest/dev/Introduction.html#ConsistencyModel), and so some operations may appear to not have an immediate effect.


## Building and running locally

```bash
docker build -t ftps-s3 . && \
docker run --rm -p 8021-8042:8021-8042 \
  -e AWS_AUTH_MECHANISM=secret_access_key \
  -e AWS_ACCESS_KEY_ID=ommitted \
  -e AWS_SECRET_ACCESS_KEY=ommitted \
  -e AWS_S3_BUCKET_REGION=eu-west-1 \
  -e AWS_S3_BUCKET_HOST=s3-eu-west-1.amazonaws.com \
  -e AWS_S3_BUCKET_NAME=my-bucket-name \
  -e AWS_S3_BUCKET_DIR_SUFFIX=/ \
  -e FTP_USERS__1__LOGIN=user \
  -e FTP_USERS__1__PASSWORD=password \
  -e FTP_COMMAND_PORT=8021 \
  -e FTP_DATA_PORTS_FIRST=4001 \
  -e FTP_DATA_PORTS_COUNT=2 \
  -e FTP_DATA_CIDR_TO_DOMAINS__1__CIDR=0.0.0.0/0 \
  -e FTP_DATA_CIDR_TO_DOMAINS__1__DOMAIN=0.0.0.0 \
  -e HEALTHCHECK_PORT=8022
  ftps-s3
```


## Building and pushing to Quay

```bash
docker build -t ftps-s3 . && \
docker tag ftps-s3:latest quay.io/uktrade/ftps-s3:latest && \
docker push quay.io/uktrade/ftps-s3:latest
```

## Building and pushing Minio, used for testing, to Quay

```bash
docker build -t ftps-s3-minio . -f Dockerfile-minio && \
docker tag ftps-s3-minio:latest quay.io/uktrade/ftps-s3-minio:latest && \
docker push quay.io/uktrade/ftps-s3-minio:latest
```
