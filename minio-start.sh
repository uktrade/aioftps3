set -e

mkdir -p minio-data/my-bucket

docker run --rm -p 9000:9000 --name minio1 -d \
  -e "MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" \
  -e "MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  -e "MINIO_REGION=us-east-1" \
  -v $PWD/minio-certs:/root/.minio/certs \
  -v $PWD/minio-data:/data \
  minio/minio server /data
