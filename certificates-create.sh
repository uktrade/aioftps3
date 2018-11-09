set -e

mkdir -p aioftps3-certs
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj /CN=selfsigned \
    -keyout aioftps3-certs/ssl.key \
    -out aioftps3-certs/ssl.crt
