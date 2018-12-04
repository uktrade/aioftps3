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
import os
import random
import re
import sys
import unittest

from aioftps3.server_main import (
    async_main,
)
from aioftps3.server_acme_route53 import (
    acme_context_manager,
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

        acme_logger = logging.getLogger('acme')
        init_ssl_context, get_ssl_context, _ = acme_context_manager(acme_logger)

        listening = asyncio.Event()
        server = loop.create_task(async_main(loop, env(), logger, init_ssl_context,
                                             get_ssl_context, listening))
        await listening.wait()

        def delete_everything(ftp):
            lines = ftp_list(ftp)
            for line in lines:
                match = re.match(LIST_REGEX, line)
                func_name = 'delete' if match[1] == 'p' else 'rmd'
                getattr(ftp, func_name)(match[6])

        await ftp_run(delete_everything, loop=loop, user='my-user', passwd=get_password())

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

        await ftp_run(nothing, loop=loop, user='my-user', passwd=get_password())
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
            await ftp_run(nothing, loop=loop, user='not-my-user', passwd=get_password())

    @async_test
    async def test_empty_list_root_directory(self):
        loop = await self.setup_manual()

        lines = await ftp_run(ftp_list, loop=loop, user='my-user', passwd=get_password())
        self.assertEqual(lines, [])

    @async_test
    async def test_stor_then_list_and_retr(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        def stor_then_list(ftp):
            ftp.storbinary('STOR my £ 👨‍👩‍👧‍👦 🍰.bin', file(contents))
            return ftp_list(ftp)

        lines = await ftp_run(stor_then_list, loop=loop, user='my-user', passwd=get_password())
        self.assertEqual(len(lines), 1)
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[1], 'p')
        self.assertEqual(match[6], 'my £ 👨‍👩‍👧‍👦 🍰.bin')

        data = bytearray()

        def on_incoming(incoming_data):
            data.extend(bytearray(incoming_data))

        def get_data(ftp):
            ftp.retrbinary('RETR my £ 👨‍👩‍👧‍👦 🍰.bin', on_incoming)

        await ftp_run(get_data, loop=loop, user='my-user', passwd=get_password())
        self.assertEqual(data, b'Some contents')

    @async_test
    async def test_if_dir_not_exist_then_no_stor(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        def stor(ftp):
            ftp.storbinary('STOR subdirectory/file.bin', file(contents))

        with self.assertRaises(error_temp):
            await ftp_run(stor, loop=loop, user='my-user', passwd=get_password())

    @async_test
    async def test_if_rest_0_can_store(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        def stor(ftp):
            ftp.sendcmd('REST 0')
            ftp.storbinary('STOR file.bin', file(contents))

        await ftp_run(stor, loop=loop, user='my-user', passwd=get_password())
        lines = await ftp_run(ftp_list, loop=loop, user='my-user', passwd=get_password())
        self.assertIn('file.bin', lines[0])
        self.assertIn(str(len(b'Some contents')), lines[0])

    @async_test
    async def test_if_rest_0_can_retr(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        data = bytearray()

        def on_incoming(incoming_data):
            data.extend(bytearray(incoming_data))

        def stor(ftp):
            ftp.storbinary('STOR file.bin', file(contents))
            ftp.sendcmd('REST 0')
            ftp.retrbinary('RETR file.bin', on_incoming)

        await ftp_run(stor, loop=loop, user='my-user', passwd=get_password())
        self.assertEqual(data, b'Some contents')

    @async_test
    async def test_if_rest_not_0_disconnects(self):
        loop = await self.setup_manual()

        def stor(ftp):
            ftp.sendcmd('REST 1')

        with self.assertRaises(BaseException):
            await ftp_run(stor, loop=loop, user='my-user', passwd=get_password())

    @async_test
    async def test_create_and_delete_directories(self):
        loop = await self.setup_manual()

        def create_directory(ftp):
            ftp.mkd('my-"  👨‍👩‍👧‍👦 🍰dir')

        await ftp_run(create_directory, loop=loop, user='my-user', passwd=get_password())

        lines = await ftp_run(ftp_list, loop=loop, user='my-user', passwd=get_password())
        self.assertEqual(len(lines), 1)
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[1], 'd')
        self.assertEqual(match[6], 'my-"  👨‍👩‍👧‍👦 🍰dir')

        def delete_directory(ftp):
            ftp.rmd('my-"  👨‍👩‍👧‍👦 🍰dir')

        await ftp_run(delete_directory, loop=loop, user='my-user', passwd=get_password())
        lines_after_del = await ftp_run(ftp_list, loop=loop, user='my-user', passwd=get_password())
        self.assertEqual(len(lines_after_del), 0)

    @async_test
    async def test_delete_must_have_file_specified(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        def stor_then_delete_all(ftp):
            ftp.storbinary('STOR my-file.bin', file(contents))
            ftp.delete('')

        with self.assertRaises(BaseException):
            await ftp_run(stor_then_delete_all, loop=loop, user='my-user', passwd=get_password())

        lines = await ftp_run(ftp_list, loop=loop, user='my-user', passwd=get_password())
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[6], 'my-file.bin')

    @async_test
    async def test_rmdir_must_have_file_specified(self):
        loop = await self.setup_manual()

        contents = (block for block in [b'Some contents'])

        def stor_then_rmdir_all(ftp):
            ftp.storbinary('STOR my-file.bin', file(contents))
            ftp.rmdir('')

        with self.assertRaises(BaseException):
            await ftp_run(stor_then_rmdir_all, loop=loop, user='my-user', passwd=get_password())

        lines = await ftp_run(ftp_list, loop=loop, user='my-user', passwd=get_password())
        match = re.match(LIST_REGEX, lines[0])
        self.assertEqual(match[6], 'my-file.bin')

    @async_test
    async def test_if_parent_dir_not_exist_then_no_mkdir(self):
        loop = await self.setup_manual()

        def mkd(ftp, directory):
            ftp.mkd(directory)

        with self.assertRaises(BaseException):
            await ftp_run(mkd, 'subdirectory/new-dir',
                          loop=loop, user='my-user', passwd=get_password())

        await ftp_run(mkd, 'subdirectory', loop=loop, user='my-user', passwd=get_password())

    @async_test
    async def test_hierarchy_stor_and_rename(self):
        loop = await self.setup_manual()

        lines_1 = []
        lines_2 = []
        lines_3 = []
        cwd_1 = None
        cwd_2 = None
        cwd_3 = None

        def stor(ftp):
            nonlocal lines_1
            nonlocal lines_2
            nonlocal lines_3
            nonlocal cwd_1
            nonlocal cwd_2
            nonlocal cwd_3

            ftp.storbinary('STOR file-1.bin', file((block for block in [b'Contents 1'])))
            ftp.mkd('👨‍👩‍👧‍👦 🍰"dir')
            ftp.cwd('👨‍👩‍👧‍👦 🍰"dir')
            cwd_1 = ftp.pwd()
            ftp.storbinary('STOR file-2.bin', file((block for block in [b'Contents 2'])))
            ftp.storbinary('STOR file-3.bin', file((block for block in [b'Contents 3'])))
            ftp.mkd('subdir')
            ftp.cwd('subdir')
            ftp.storbinary('STOR file-4.bin', file((block for block in [b'Contents 4'])))
            ftp.cwd('..')
            ftp.cwd('..')
            ftp.rename('👨‍👩‍👧‍👦 🍰"dir', '"another dir"')
            lines_1 = ftp_list(ftp)
            ftp.cwd('"another dir"')
            cwd_2 = ftp.pwd()
            lines_2 = ftp_list(ftp)
            ftp.cwd('subdir')
            cwd_3 = ftp.pwd()
            lines_3 = ftp_list(ftp)

        await ftp_run(stor, loop=loop, user='my-user', passwd=get_password())

        self.assertEqual(cwd_1, '/👨‍👩‍👧‍👦 🍰"dir')
        self.assertEqual(cwd_2, '/"another dir"')
        self.assertEqual(cwd_3, '/"another dir"/subdir')
        self.assertEqual(len(lines_1), 2)
        self.assertIn('"another dir"', lines_1[0])
        self.assertIn('file-1.bin', lines_1[1])
        self.assertEqual(len(lines_2), 3)
        self.assertIn('subdir', lines_2[0])
        self.assertIn('file-2.bin', lines_2[1])
        self.assertIn('file-3.bin', lines_2[2])
        self.assertEqual(len(lines_3), 1)
        self.assertIn('file-4.bin', lines_3[0])

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
            ftp.storbinary('STOR my £" 👨‍👩‍👧‍👦 🍰.bin', random_file())

        await ftp_run(stor, loop=loop, user='my-user', passwd=get_password())

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
            ftp.retrbinary('RETR my £" 👨‍👩‍👧‍👦 🍰.bin', on_incoming)

        await ftp_run(get_data, loop=loop, user='my-user', passwd=get_password())
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
        'AWS_S3_BUCKET__REGION': 'us-east-1',
        'AWS_S3_BUCKET__HOST': 'localhost:9000',
        'AWS_S3_BUCKET__NAME': 'my-bucket',
        'AWS_S3_BUCKET__DIR_SUFFIX': '/.s3keep',
        'AWS_S3_BUCKET__VERIFY_CERTS': 'false',
        'AWS_S3_ACME_BUCKET__REGION': 'us-east-1',
        'AWS_S3_ACME_BUCKET__HOST': 'localhost:9000',
        'AWS_S3_ACME_BUCKET__NAME': 'my-bucket-acme',
        'AWS_S3_ACME_BUCKET__VERIFY_CERTS': 'false',
        'FTP_USERS__1__LOGIN': 'my-user',
        'FTP_USERS__1__PASSWORD_HASHED': 'N3HmktqTFxH6RArbScmnwQH3/S3Ow593NFdSVrftp2M=',
        'FTP_USERS__1__PASSWORD_SALT':
            'np1RamJvq2S9YwvvqC5o59fQDFgn4IcBfzmSwJWHvoPMwWCVRUzMePceRbL9FMOT',
        'FTP_COMMAND_PORT': '8021',
        'FTP_DATA_PORTS_FIRST': '4001',
        'FTP_DATA_PORTS_COUNT': '2',
        'FTP_DATA_CIDR_TO_DOMAINS__1__CIDR': '0.0.0.0/0',
        'FTP_DATA_CIDR_TO_DOMAINS__1__DOMAIN': '127.0.0.1',
        'HEALTHCHECK_PORT': '8022',
        'HOME': os.environ['HOME'],
    }


def get_password():
    return 'kOcAeOQ7Pc'
