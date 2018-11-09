import asyncio
from ftplib import (
    FTP_TLS,
    error_perm,
)
import logging
import ssl
import sys
import unittest

from aioftps3.server_main import (
    async_main,
)


def async_test(func):
    def wrapper(*args, **kwargs):
        future = func(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper


class TestAioFtpS3(unittest.TestCase):

    def add_async_cleanup(self, loop, coroutine):
        self.addCleanup(loop.run_until_complete, coroutine())

    async def setup_manual(self):
        loop = asyncio.get_event_loop()

        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ssl_context.load_cert_chain('aioftps3-certs/ssl.crt', keyfile='aioftps3-certs/ssl.key')

        server = loop.create_task(async_main(loop, env(), logger, ssl_context))

        async def cancel_server():
            server.cancel()
            await asyncio.sleep(0)

        self.add_async_cleanup(loop, cancel_server)

        return loop

    @async_test
    async def test_if_correct_creds_login_succeeds(self):
        loop = await self.setup_manual()

        def connect():
            with FTP_TLS() as ftp:
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.quit()

        await loop.run_in_executor(None, connect)
        # Will raise if fails

    @async_test
    async def test_if_bad_pass_login_fails(self):
        loop = await self.setup_manual()

        def connect():
            with FTP_TLS() as ftp:
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='not-my-password')
                ftp.quit()

        with self.assertRaises(error_perm):
            await loop.run_in_executor(None, connect)

    @async_test
    async def test_if_bad_user_login_fails(self):
        loop = await self.setup_manual()

        def connect():
            with FTP_TLS() as ftp:
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='not-my-user', passwd='my-password')
                ftp.quit()

        with self.assertRaises(error_perm):
            await loop.run_in_executor(None, connect)


def env():
    return {
        'AWS_AUTH_MECHANISM': 'secret_access_key',
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'AWS_S3_BUCKET_REGION': 'us-east-1',
        'AWS_S3_BUCKET_HOST': 'localhost:9000',
        'AWS_S3_BUCKET_NAME': 'my-bucket',
        'FTP_USERS__1__LOGIN': 'my-user',
        'FTP_USERS__1__PASSWORD': 'my-password',
        'FTP_COMMAND_PORT': '8021',
        'FTP_DATA_PORTS_FIRST': '4001',
        'FTP_DATA_PORTS_COUNT': '2',
        'FTP_DATA_CIDR_TO_DOMAINS__1__CIDR': '0.0.0.0/0',
        'FTP_DATA_CIDR_TO_DOMAINS__1__DOMAIN': '127.0.0.1',
        'HEALTHCHECK_PORT': '8022',
    }
