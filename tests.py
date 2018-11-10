import asyncio
from collections import (
    namedtuple,
)
from ftplib import (
    FTP_TLS,
    error_perm,
    error_temp,
)
import logging
import random
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

        def delete_everything(ftp):
            lines = ftp_list(ftp)
            for line in lines:
                match = re.match(LIST_REGEX, line)
                func_name = 'delete' if match[1] == 'p' else 'rmd'
                getattr(ftp, func_name)(match[6])

        await ftp_run(delete_everything, loop=loop, user='my-user', passwd='my-password')

        async def cancel_server():
            server.cancel()
            await asyncio.sleep(0)

        self.add_async_cleanup(loop, cancel_server)

        return loop

    @async_test
    async def test_if_correct_creds_login_succeeds(self):
        loop = await self.setup_manual()

        def nothing(_):
            pass

        await ftp_run(nothing, loop=loop, user='my-user', passwd='my-password')
        # Will raise if fails

    @async_test
    async def test_if_bad_pass_login_fails(self):
        loop = await self.setup_manual()

        def nothing(_):
            pass

        with self.assertRaises(error_perm):
            await ftp_run(nothing, loop=loop, user='my-user', passwd='not-my-password')

    @async_test
    async def test_if_bad_user_login_fails(self):
        loop = await self.setup_manual()

        def nothing(_):
            pass

        with self.assertRaises(error_perm):
            await ftp_run(nothing, loop=loop, user='not-my-user', passwd='my-password')

    @async_test
    async def test_empty_list_root_directory(self):
        loop = await self.setup_manual()

        lines = await ftp_run(ftp_list, loop=loop, user='my-user', passwd='my-password')
        self.assertEqual(lines, [])

    @async_test
    async def test_stor_then_list_and_retr(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        def stor_then_list(ftp):
            ftp.storbinary('STOR my £ 👨‍👩‍👧‍👦 🍰.bin', file(contents))
            return ftp_list(ftp)

        lines = await ftp_run(stor_then_list, loop=loop, user='my-user', passwd='my-password')
        self.assertEqual(len(lines), 1)
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[1], 'p')
        self.assertEqual(match[6], 'my £ 👨‍👩‍👧‍👦 🍰.bin')

        data = bytearray()

        def on_incoming(incoming_data):
            data.extend(bytearray(incoming_data))

        def get_data(ftp):
            ftp.retrbinary('RETR my £ 👨‍👩‍👧‍👦 🍰.bin', on_incoming)

        await ftp_run(get_data, loop=loop, user='my-user', passwd='my-password')
        self.assertEqual(data, b'Some contents')

    @async_test
    async def test_if_dir_not_exist_then_no_stor(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        def stor(ftp):
            ftp.storbinary('STOR subdirectory/file.bin', file(contents))

        with self.assertRaises(error_temp):
            await ftp_run(stor, loop=loop, user='my-user', passwd='my-password')

    @async_test
    async def test_create_and_delete_directories(self):
        loop = await self.setup_manual()

        def create_directory(ftp):
            ftp.mkd('my-dir')

        await ftp_run(create_directory, loop=loop, user='my-user', passwd='my-password')

        lines = await ftp_run(ftp_list, loop=loop, user='my-user', passwd='my-password')
        self.assertEqual(len(lines), 1)
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[1], 'd')
        self.assertEqual(match[6], 'my-dir')

        def delete_directory(ftp):
            ftp.rmd('my-dir')

        await ftp_run(delete_directory, loop=loop, user='my-user', passwd='my-password')
        lines_after_del = await ftp_run(ftp_list, loop=loop, user='my-user', passwd='my-password')
        self.assertEqual(len(lines_after_del), 0)

    @async_test
    async def test_if_parent_dir_not_exist_then_no_mkdir(self):
        loop = await self.setup_manual()

        def mkd(ftp, directory):
            ftp.mkd(directory)

        with self.assertRaises(BaseException):
            await ftp_run(mkd, 'subdirectory/new-dir',
                          loop=loop, user='my-user', passwd='my-password')

        await ftp_run(mkd, 'subdirectory', loop=loop, user='my-user', passwd='my-password')

    @async_test
    async def test_100mb_file(self):
        loop = await self.setup_manual()

        def random_bytes(num_bytes):
            return bytes(random.getrandbits(8) for _ in range(num_bytes))

        def random_file():
            random.seed(a=1234)
            contents = (random_bytes(128) * 64 for _ in range(0, 12928))
            return file(contents)

        def stor(ftp):
            ftp.storbinary('STOR my £ 👨‍👩‍👧‍👦 🍰.bin', random_file())

        await ftp_run(stor, loop=loop, user='my-user', passwd='my-password')

        correct_file = random_file()
        correct = b''
        downloaded = b''
        all_equal = True
        num_checked = 0

        def on_incoming(incoming):
            nonlocal correct
            nonlocal downloaded
            nonlocal all_equal
            nonlocal num_checked

            downloaded += incoming

            while len(correct) < len(downloaded):
                correct += correct_file.read(None)

            num_to_check = min(len(downloaded), len(correct))
            all_equal = all_equal and downloaded[:num_to_check] == correct[:num_to_check]

            downloaded = downloaded[num_to_check:]
            correct = correct[num_to_check:]
            num_checked += num_to_check

        def get_data(ftp):
            ftp.retrbinary('RETR my £ 👨‍👩‍👧‍👦 🍰.bin', on_incoming)

        await ftp_run(get_data, loop=loop, user='my-user', passwd='my-password')
        self.assertEqual(num_checked, 105906176)
        self.assertTrue(all_equal)


def file(generator):
    def read(_):
        try:
            return next(generator)
        except StopIteration:
            return b''

    return Readable(read=read)


def ftp_list(ftp):
    lines = []

    def on_line(line):
        lines.append(line)

    ftp.dir(on_line)

    return lines


async def ftp_run(func, *args, loop, user, passwd):
    def task():
        with FTP_TLS() as ftp:
            ftp.encoding = 'utf-8'
            ftp.connect(host='localhost', port=8021)
            ftp.login(user=user, passwd=passwd)
            ftp.prot_p()
            return func(ftp, *args)

    return await loop.run_in_executor(None, task)


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
