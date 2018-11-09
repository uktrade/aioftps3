echo "Waiting for Minio..."
wget --waitretry=1 --tries=120 --server-response --retry-connrefused --no-check-certificate -O- https://127.0.0.1:9000/
RESULT=$?
echo $RESULT
if [ $RESULT -ne 8 ] && [ $RESULT -ne 4 ]; then
    exit
fi
echo "Minio is running"

set -e

python -m unittest -v -- "$@"
