set -e

mkdir -p minio-certs
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj /CN=selfsigned \
    -keyout minio-certs/private.key \
    -out minio-certs/public.crt

mkdir -p aioftps3-certs
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj /CN=selfsigned \
    -keyout aioftps3-certs/ssl.key \
    -out aioftps3-certs/ssl.crt
