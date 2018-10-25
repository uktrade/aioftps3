# ftps-s3

## Building and running locally

```bash
docker build -t ftps-s3 . && docker run --rm -p 8021-8042:8021-8042 ftps-s3
```

## Building and pushing to Quay

```bash
docker build -t ftps-s3 . && \
docker tag ftps-s3:latest quay.io/uktrade/ftps-s3:latest && \
docker push quay.io/uktrade/ftps-s3:latest
```
