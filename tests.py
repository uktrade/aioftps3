import asyncio
import os
import ssl
import shutil
import unittest

import aioftp
import aiohttp

import aioftps3


def async_test(func):
    def wrapper(*args, **kwargs):
        future = func(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper


def delete_dir_contents(path):
    for root, dirs, files in os.walk(path):
        for file in files:
            os.unlink(os.path.join(root, file))
        for directory in dirs:
            shutil.rmtree(os.path.join(root, directory))


class TestS3PathIO(unittest.TestCase):

    def add_async_cleanup(self, loop, coroutine):
        self.addCleanup(loop.run_until_complete, coroutine())

    async def setup_manual(self):
        delete_dir_contents('minio-data/my-bucket')

        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        self.add_async_cleanup(loop, session.close)

        context = ssl.SSLContext()
        context.load_cert_chain('aioftps3-certs/ssl.crt',
                                keyfile='aioftps3-certs/ssl.key')

        credentials = aioftps3.s3_path_io_secret_access_key_credentials(
            access_key_id='AKIAIOSFODNN7EXAMPLE',
            secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        )
        bucket = aioftps3.s3_path_io_bucket(
            region='us-east-1',
            host='localhost:9000',
            verify_certs=False,
            name='my-bucket',
        )
        server = aioftp.Server(
            loop=loop,
            ssl=context,
            path_io_factory=aioftps3.s3_path_io_factory(
                session=session, credentials=credentials, bucket=bucket),
            data_ports=range(8022, 8042),
            block_size=64 * 1024 * 1024,
        )
        await server.start('0.0.0.0', 8021)
        self.add_async_cleanup(loop, server.close)

    @async_test
    async def test_empty_bucket(self):
        await self.setup_manual()

        context = ssl.SSLContext()
        async with aioftp.ClientSession('127.0.0.1', port=8021, user='user', password='anon@',
                                        ssl=context) as client:
            results = await client.list()

        self.assertEqual(results, [])
