set -e

echo "Waiting for Minio..."
wget --waitretry=1 --retry-connrefused  --no-check-certificate -O- -header="Accept: text/html" https://127.0.0.1:9000/ &> /dev/null
echo "Minio is running"

python -m unittest -v -- "$@"
