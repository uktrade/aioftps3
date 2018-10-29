# aioftps3

FTP in front of AWS S3, using [asyncio](https://docs.python.org/3/library/asyncio.html), [aioftp](https://github.com/aio-libs/aioftp) and [aiohttp](https://github.com/aio-libs/aiohttp).

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

- As few dependencies as is reasonable: aioftp, aiohttp, and their dependencies. Boto 3 is _not_ used.

- May not behave well if upload to the server is faster than its upload to S3.

- There is some locking to deal with the same files being operated on concurrently. However...

- .... it does nothing to deal with [eventual consistency of S3](https://docs.aws.amazon.com/AmazonS3/latest/dev/Introduction.html#ConsistencyModel), and so some operations may appear to not have an immediate effect.

## Building and running locally

```bash
docker build -t ftps-s3 . && \
docker run --rm -p 8021-8042:8021-8042 \
  -e AWS_ACCESS_KEY_ID=ommitted \
  -e AWS_SECRET_ACCESS_KEY=ommitted \
  -e AWS_S3_BUCKET_REGION=eu-west-1 \
  -e AWS_S3_BUCKET_HOST=s3-eu-west-1.amazon.aws.com \
  -e AWS_S3_BUCKET_NAME=my-bucket-name
  ftps-s3
```

## Building and pushing to Quay

```bash
docker build -t ftps-s3 . && \
docker tag ftps-s3:latest quay.io/uktrade/ftps-s3:latest && \
docker push quay.io/uktrade/ftps-s3:latest
```
