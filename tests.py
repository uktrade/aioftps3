import asyncio
from collections import (
    namedtuple,
)
from ftplib import (
    FTP_TLS,
    error_perm,
)
import logging
import re
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


Readable = namedtuple('Readable', ['read'])
LIST_REGEX = '^(p|d)rw(?:-|x)rw(?:-|x)rw(?:-|x) 1 none none +(\\d+) ([a-zA-Z]{3}) +' \
             '(\\d+) (\\d\\d:\\d\\d) (.*)'


class TestAioFtpS3(unittest.TestCase):

    def add_async_cleanup(self, loop, coroutine):
        self.addCleanup(loop.run_until_complete, coroutine())

    async def setup_manual(self):
        loop = asyncio.get_event_loop()

        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        logger.handlers = []
        logger.addHandler(handler)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ssl_context.load_cert_chain('aioftps3-certs/ssl.crt', keyfile='aioftps3-certs/ssl.key')

        server = loop.create_task(async_main(loop, env(), logger, ssl_context))

        def delete_everything():
            with FTP_TLS() as ftp:
                ftp.encoding = 'utf-8'
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.prot_p()
                lines = ftp_list(ftp)
                for line in lines:
                    match = re.match(LIST_REGEX, line)
                    func_name = 'delete' if match[1] == 'p' else 'rmd'
                    getattr(ftp, func_name)(match[6])

        await loop.run_in_executor(None, delete_everything)

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

    @async_test
    async def test_empty_list_root_directory(self):
        loop = await self.setup_manual()

        def get_dir_lines():
            with FTP_TLS() as ftp:
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.prot_p()
                return ftp_list(ftp)

        lines = await loop.run_in_executor(None, get_dir_lines)
        self.assertEqual(lines, [])

    @async_test
    async def test_stor_then_list_and_retr(self):
        loop = await self.setup_manual()

        def file():
            contents = (block for block in [b'Some contents'])

            def read(_):
                try:
                    return next(contents)
                except StopIteration:
                    return b''

            return Readable(read=read)

        def get_dir_lines():
            with FTP_TLS() as ftp:
                ftp.encoding = 'utf-8'
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.prot_p()
                ftp.storbinary('STOR my £ 👨‍👩‍👧‍👦 🍰.bin', file())
                return ftp_list(ftp)

        lines = await loop.run_in_executor(None, get_dir_lines)
        self.assertEqual(len(lines), 1)
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[1], 'p')
        self.assertEqual(match[6], 'my £ 👨‍👩‍👧‍👦 🍰.bin')

        data = bytearray()

        def on_incoming(incoming_data):
            data.extend(bytearray(incoming_data))

        def get_data():
            with FTP_TLS() as ftp:
                ftp.encoding = 'utf-8'
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.prot_p()
                ftp.retrbinary('RETR my £ 👨‍👩‍👧‍👦 🍰.bin', on_incoming)

        await loop.run_in_executor(None, get_data)
        self.assertEqual(data, b'Some contents')

    @async_test
    async def test_create_and_delete_directories(self):
        loop = await self.setup_manual()

        def create_directory():
            with FTP_TLS() as ftp:
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.mkd('my-dir')

        await loop.run_in_executor(None, create_directory)

        def get_dir_lines():
            with FTP_TLS() as ftp:
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.prot_p()
                return ftp_list(ftp)

        lines = await loop.run_in_executor(None, get_dir_lines)
        self.assertEqual(len(lines), 1)
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[1], 'd')
        self.assertEqual(match[6], 'my-dir')

        def delete_directory():
            with FTP_TLS() as ftp:
                ftp.connect(host='localhost', port=8021)
                ftp.login(user='my-user', passwd='my-password')
                ftp.prot_p()
                ftp.rmd('my-dir')

        await loop.run_in_executor(None, delete_directory)
        lines_after_del = await loop.run_in_executor(None, get_dir_lines)
        self.assertEqual(len(lines_after_del), 0)


def ftp_list(ftp):
    lines = []

    def on_line(line):
        lines.append(line)

    ftp.dir(on_line)

    return lines


def env():
    return {
        'AWS_AUTH_MECHANISM': 'secret_access_key',
        'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
        'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'AWS_S3_BUCKET_REGION': 'us-east-1',
        'AWS_S3_BUCKET_HOST': 'localhost:9000',
        'AWS_S3_BUCKET_NAME': 'my-bucket',
        'AWS_S3_BUCKET_DIR_SUFFIX': '/.s3keep',
        'FTP_USERS__1__LOGIN': 'my-user',
        'FTP_USERS__1__PASSWORD': 'my-password',
        'FTP_COMMAND_PORT': '8021',
        'FTP_DATA_PORTS_FIRST': '4001',
        'FTP_DATA_PORTS_COUNT': '2',
        'FTP_DATA_CIDR_TO_DOMAINS__1__CIDR': '0.0.0.0/0',
        'FTP_DATA_CIDR_TO_DOMAINS__1__DOMAIN': '127.0.0.1',
        'HEALTHCHECK_PORT': '8022',
    }
