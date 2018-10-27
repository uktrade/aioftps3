# aioftps3

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
