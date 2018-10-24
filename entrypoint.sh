#!/bin/sh

set -e

echo "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" > ~/.passwd-s3fs
chmod 600  ~/.passwd-s3fs

mkdir -p ~/ftp-root
/usr/bin/s3fs ftps-dev ~/ftp-root -o nosuid,nonempty,nodev,allow_other,endpoint=eu-west-2,url=https://s3-eu-west-2.amazonaws.com

exec "$@"
