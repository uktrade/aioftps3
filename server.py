import logging
import ssl
import os
import sys

import asyncio
import aioftp
import aiohttp
import s3pathio


def main():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    context = ssl.SSLContext()
    context.load_cert_chain(f'{os.environ["HOME"]}/ssl.crt',
                            keyfile=f'{os.environ["HOME"]}/ssl.key')

    loop = asyncio.get_event_loop()
    credentials = s3pathio.s3_path_io_secret_access_key_credentials(
        access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
        secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
    )
    bucket = s3pathio.s3_path_io_bucket(
        region=os.environ['AWS_S3_BUCKET_REGION'],
        host=os.environ['AWS_S3_BUCKET_HOST'],
        name=os.environ['AWS_S3_BUCKET_NAME'],
    )
    session = aiohttp.ClientSession(loop=loop)

    server = aioftp.Server(
        loop=loop,
        ssl=context,
        path_io_factory=s3pathio.s3_path_io_factory(
            session=session, credentials=credentials, bucket=bucket),
        data_ports=range(8022, 8042),
    )
    loop.run_until_complete(server.start('0.0.0.0', 8021))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(server.close())
        loop.close()


main()
