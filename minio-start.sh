set -e

openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj /CN=selfsigned \
    -keyout route53.key \
    -out route53.crt

docker build -t ftps-s3-minio . -f Dockerfile-minio
docker run --rm -p 9000:9000 --name minio1 -d \
  -e "MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" \
  -e "MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  -e "MINIO_REGION=us-east-1" \
  ftps-s3-minio server /test-data
