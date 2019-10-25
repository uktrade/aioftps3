import asyncio
from collections import (
    namedtuple,
)
from ftplib import (
    FTP_TLS,
)
import logging
import os
import sys
import time

from aiohttp import (
    web,
)


Readable = namedtuple('Readable', ['read'])


async def async_main(loop, logger, healthcheck_port, ftp_host, ftp_port, ftp_user, ftp_password):

    async def handle_alb_healthcheck(_):
        return web.Response(text='OK')

    async def handle_pingdom_healthcheck(_):
        contents = b'healthcheck-test-contents'
        contents_generator = (block for block in [contents])
        file_name = '__HEALTHCHECK_PLEASE_IGNORE__'

        data = bytearray()

        def on_incoming(incoming_data):
            data.extend(bytearray(incoming_data))

        def test_ftp():
            logger.debug('Connecting to %s', ftp_host)
            with FTP_TLS() as ftp:
                ftp.encoding = 'utf-8'
                ftp.connect(host=ftp_host, port=ftp_port)
                logger.debug('Connecting as %s...', ftp_user)
                ftp.login(user=ftp_user, passwd=ftp_password)
                logger.debug('Connecting as %s... (done)', ftp_user)
                ftp.prot_p()  # pylint: disable=no-member

                # In case the previous healthcheck died before we deleted the file
                logger.debug('Fetching list...')
                original_list = ftp_list(ftp)
                logger.debug('Fetching list... (done)')
                in_original_list = [line for line in original_list if file_name in line]
                if in_original_list:
                    ftp.delete(file_name)
                    # Very rough way to deal with eventual consistency. Should be rare that
                    # we hit this case however
                    time.sleep(2)

                logger.debug('STOR %s...', file_name)
                ftp.storbinary(f'STOR {file_name}', ftp_file(contents_generator))
                logger.debug('STOR %s... (done)', file_name)

                logger.debug('Fetching list again...')
                after_store_list = ftp_list(ftp)
                logger.debug('Fetching list again...(done')

                in_after_store_list = [line for line in after_store_list if file_name in line]
                if not in_after_store_list:
                    raise Exception('File not stored')

                logger.debug('RETR %s...', file_name)
                ftp.retrbinary(f'RETR {file_name}', on_incoming)
                logger.debug('RETR %s... (done)', file_name)

                if bytes(data) != contents:
                    raise Exception('File stored incorrectly')

                logger.debug('Deleting %s...', file_name)
                ftp.delete(file_name)
                logger.debug('Deleting %s... (done)', file_name)

        await loop.run_in_executor(None, test_ftp)
        return web.Response(text='OK')

    app = web.Application()
    app.add_routes([
        web.get('/alb_healthcheck', handle_alb_healthcheck),
        web.get('/pingdom_healthcheck', handle_pingdom_healthcheck),
    ])

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', healthcheck_port)
    await site.start()


def ftp_file(generator):
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


def main():
    healthcheck_port = int(os.environ['HEALTHCHECK_PORT'])

    ftp_host = os.environ['FTP_HOST']
    ftp_port = int(os.environ['FTP_COMMAND_PORT'])
    ftp_user = os.environ['FTP_USER']
    ftp_password = os.environ['FTP_PASSWORD']

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    loop = asyncio.get_event_loop()
    loop.create_task(async_main(loop, logger, healthcheck_port,
                                ftp_host, ftp_port, ftp_user, ftp_password))
    loop.run_forever()


if __name__ == '__main__':
    main()
