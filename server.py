import asyncio
import ipaddress
import logging
from pathlib import (
    PurePosixPath,
)
import os
import random
import signal
from ssl import (
    PROTOCOL_TLSv1_2,
    SSLContext,
)
import stat
import sys

import aiodns
import aiohttp

from server_logger import (
    get_child_logger,
    get_logger_with_context,
    logged,
)

from server_s3 import (
    get_s3_bucket,
    get_s3_context,
    get_s3_secret_access_key_credentials,
    s3_delete,
    s3_get,
    s3_list,
    s3_mkdir,
    s3_put,
    s3_rmdir,
)

from server_socket import (
    recv_lines,
    recv_until_close,
    send_all,
    send_line,
    server,
    shutdown_socket,
    ssl_complete_handshake,
    ssl_get_socket,
    ssl_unwrap_socket,
)

from server_utils import (
    constant_time_compare,
    normalise_environment,
    timeout,
)

# How long a command has to complete
COMMAND_TIMEOUT_SECONDS = 15

# How long a client has to connect to the PASV server once it's requested
DATA_CONNECT_TIMEOUT_SECONDS = 10

# How long a client has to issue the command to use the PASV server after
# the client has connected to it
DATA_COMMAND_TIMEOUT_SECONDS = 2

COMMAND_CHUNK_BYTES = 1024
DATA_CHUNK_SIZE = 1024 * 64


# We are very specific in terms of tasks created:
#
# - A task for the main server
# - Two tasks for each client connection:
#   - One for receiving and processing incoming commands
#   - One for sending outgoing command responses
# - A task for each client's data server: only running until the data transfer
#   started
# - A task for each data connection from the client: any more than one will
#   be very short-lived, e.g. if multiple clients connect in the brief amount
#   amount of time that the server has started, but not yet started the data
#   transfer, the second will close the connection and end the task
#
# The separation of incoming/outgoing on the client command connection is a
# consequence of wanting outgoing command responses from the _data_ task.
# Sending data is not atomic, e.g. it can decide to send a single byte at a
# time and yield to other tasks, so there could be a risk of sending corrupt
# responses unless we ensure only a response is sent at time. One way of doing
# this is a dedicated task for outgoing command data.
#
# Each task also keeps track of the tasks that it creates: on cancellation of
# the main task, it's the responsibility of each task to cancel its child
# tasks.
#
# Communication to S3 can happen from any task. There is locking to try to
# prevent race conditions


async def on_client_connect(logger, loop, ssl_context, sock, get_data_ip, data_ports,
                            is_data_sock_ok, is_user_correct, is_password_correct, s3_context):
    user = None
    is_authenticated = False
    ssl_sock = None
    cwd = PurePosixPath('/')

    data_server = None
    data_client = None
    data_port = None
    data_funcs = asyncio.Queue(maxsize=1)

    # Multiple concurrent sends on the same socket would be bad, so we only
    # allow them to be sent from a dedicated task, but other tasks can
    # queue them up
    command_responses = asyncio.Queue(maxsize=1)

    # Glue to lower level functions

    def get_sock():
        return ssl_sock if ssl_sock is not None else sock

    async def send_command_responses():
        while True:
            response = await command_responses.get()
            logger.debug('Out: %s', response)
            try:
                await send_line(loop, get_sock, COMMAND_CHUNK_BYTES, response)
            finally:
                command_responses.task_done()

    def command_sock_recv_lines():
        return recv_lines(loop, get_sock, COMMAND_CHUNK_BYTES)

    async def data_sock_send_line(data_sock, line):
        await send_line(loop, lambda: data_sock, DATA_CHUNK_SIZE, line)

    async def data_sock_send_all(data_sock, data):
        await send_all(loop, lambda: data_sock, DATA_CHUNK_SIZE, memoryview(data))

    # Deliberate quitting: to keep the number of code paths as small as
    # possible, uses the same method as if the whole server is shutting down,
    # using cancellation

    async def cancel_current_task():
        asyncio.current_task().cancel()
        # Causes the cancel exception to be raised, right here
        await asyncio.sleep(0)

    # Path manipulation

    def to_absolute_path(arg):
        requested_path = arg.decode('utf-8')

        absolute = \
            PurePosixPath(requested_path) if requested_path[0] == '/' else \
            cwd / PurePosixPath(requested_path)

        return absolute

    # Commands

    async def command_auth(_):
        nonlocal ssl_sock
        await command_responses.put(b'234 TLS negotiation will follow.')
        await command_responses.join()
        with logged(logger, 'Performing TLS handshake', []):
            ssl_sock = ssl_get_socket(ssl_context, sock)
            await ssl_complete_handshake(loop, ssl_sock)

    async def command_syst(_):
        await command_responses.put(b'215 UNIX Type: L8')

    async def command_type(_):
        await command_responses.put(b'200 Command okay.')

    async def command_feat(_):
        await command_responses.put(b'211-System status, or system help reply.')
        await command_responses.put(b'UTF8')
        await command_responses.put(b'211 End')

    async def command_opts(_):
        await command_responses.put(b'200 Command okay.')

    async def command_pbsz(_):
        await command_responses.put(b'200 Command okay.')

    async def command_prot(_):
        await command_responses.put(b'200 Command okay.')

    async def command_stat(_):
        await command_responses.put(b'211')

    async def command_user(arg):
        nonlocal user

        attempted_user = arg.decode('utf-8')
        is_ok = await is_user_correct(attempted_user)

        if not is_ok:
            await command_responses.put(b'530 Not logged in.')
            await command_responses.join()
            await cancel_current_task()

        user = attempted_user
        await command_responses.put(b'331 User name okay, need password.')

    async def command_pass(arg):
        nonlocal is_authenticated

        attempted_password = arg.decode('utf-8')
        is_ok = await is_password_correct(user, attempted_password)

        if not is_ok:
            await command_responses.put(b'530 Not logged in.')
            await command_responses.join()
            await cancel_current_task()

        is_authenticated = True
        await command_responses.put(b'230 User logged in, proceed.')

    async def command_pwd(_):
        await command_responses.put(b'257 "%s"' % cwd.as_posix().encode('utf-8'))

    async def command_mkd(arg):
        s3_path = to_absolute_path(arg)
        await s3_mkdir(s3_context, s3_path)
        await command_responses.put(b'230 Requested file action okay, completed.')

    async def command_rmd(arg):
        s3_path = to_absolute_path(arg)
        await s3_rmdir(s3_context, s3_path)
        await command_responses.put(b'230 Requested file action okay, completed.')

    async def command_cdup(_):
        nonlocal cwd
        cwd = cwd.parent
        await command_responses.put(b'230 Requested file action okay, completed.')

    async def command_cwd(arg):
        nonlocal cwd
        cwd = to_absolute_path(arg)
        await command_responses.put(b'230 Requested file action okay, completed.')

    async def command_dele(arg):
        s3_path = to_absolute_path(arg)
        await s3_delete(s3_context, s3_path)
        await command_responses.put(b'230 Requested file action okay, completed.')

    async def command_list(_):
        s3_path = cwd

        async def data_task_func(ssl_data_sock):
            async for list_path in await s3_list(s3_context, s3_path):
                await data_sock_send_line(ssl_data_sock, (
                    stat.filemode(list_path.stat.st_mode) + ' ' +
                    str(list_path.stat.st_nlink) + ' ' +
                    'none ' +
                    'none ' +
                    str(list_path.stat.st_size) + ' ' +
                    list_path.stat.st_mtime.strftime('%b %e %H:%M') + ' ' +
                    list_path.name
                ).encode('utf-8'))

        await data_funcs.put(data_task_func)
        await command_responses.put(b'150 File status okay; about to open data connection.')

    async def command_retr(arg):
        s3_path = to_absolute_path(arg)

        async def data_task_func(ssl_data_sock):
            async for data in s3_get(s3_context, s3_path, DATA_CHUNK_SIZE):
                await data_sock_send_all(ssl_data_sock, data)

        await data_funcs.put(data_task_func)
        await command_responses.put(b'150 File status okay; about to open data connection.')

    async def command_stor(arg):
        s3_path = to_absolute_path(arg)

        async def data_task_func(ssl_data_sock):
            async with s3_put(s3_context, s3_path) as write:
                async for data in recv_until_close(loop, lambda: ssl_data_sock, DATA_CHUNK_SIZE):
                    await write(data)

        await data_funcs.put(data_task_func)
        await command_responses.put(b'150 File status okay; about to open data connection.')

    async def command_pasv(_):
        nonlocal data_port
        nonlocal data_server

        data_client_connected = asyncio.Future()

        async def on_data_client_connect(data_client_logger, __, ____, data_sock):
            nonlocal data_client

            # Raise if this is the second, and so unexpected, client
            data_client_connected.set_result(None)

            if not await is_data_sock_ok(get_sock(), data_sock):
                raise Exception('Data sock is not ok: could be an attack')

            data_client = asyncio.current_task()

            # If we do have an expected data client, we cancel the server
            # to prevent more connections
            data_server.cancel()
            await asyncio.sleep(0)

            try:
                with logged(data_client_logger, 'Performing TLS handshake', []):
                    ssl_data_sock = ssl_get_socket(ssl_context, data_sock)
                    await ssl_complete_handshake(loop, ssl_data_sock)

                async with timeout(loop, DATA_COMMAND_TIMEOUT_SECONDS):
                    func = await data_funcs.get()

                await func(ssl_data_sock)
            finally:
                data_funcs.task_done()
                data_client = None
                await command_responses.put(b'226 Closing data connection.')
                data_sock = await ssl_unwrap_socket(loop, ssl_data_sock, data_sock)
                await shutdown_socket(loop, data_sock)

        async def on_data_server_cancel(_):  # Client tasks passed
            # Since cancellation of the data server is triggered at the
            # beginning of the data client task, which would call this
            # function, we don't cancel the child task here, otherwise we'll
            # be cancelling what we want to be running. On main server cancel,
            # the data client task is cancelled, near the bottom of
            # on_client_connect
            pass

        def on_data_server_close(_):
            nonlocal data_port
            nonlocal data_server

            data_ports.add(data_port)
            data_port = None
            data_server = None

        data_port = random.sample(data_ports, 1)[0]
        data_ports.remove(data_port)
        data_logger = get_child_logger(logger, 'data')
        data_server = loop.create_task(server(data_logger, loop, ssl_context, data_port,
                                              on_data_client_connect, on_data_server_cancel))
        data_server.add_done_callback(on_data_server_close)

        data_port_higher = str(data_port >> 8).encode('ascii')
        data_port_lower = str(data_port & 0xff).encode('ascii')
        data_ip = [part.encode('ascii') for part in (await get_data_ip(get_sock())).split('.')]
        response = b'227 Entering Passive Mode (%s,%s,%s,%s,%s,%s)' % (
            data_ip[0], data_ip[1], data_ip[2], data_ip[3],
            data_port_higher, data_port_lower)

        await command_responses.put(response)

        try:
            async with timeout(loop, DATA_CONNECT_TIMEOUT_SECONDS):
                await data_client_connected
        except BaseException:
            await cancel_data_tasks()
            raise

    async def command_quit(_):
        await command_responses.put(b'221 Service closing control connection.')
        await command_responses.join()
        await cancel_current_task()

    async def cancel_data_tasks():
        for task in [task for task in [data_client, data_server] if task]:
            task.cancel()
            await asyncio.sleep(0)

    def get_command_func(parent_locals, command):
        command_lower = command.lower()
        return parent_locals[f'command_{command_lower}']

    def is_implemented(parent_locals, command):
        command_lower = command.lower()
        return f'command_{command_lower}' in parent_locals

    def is_good_sequence(command):
        is_ssl = ssl_sock is not None

        is_good = \
            (command == 'AUTH' and not is_ssl and not is_authenticated and not user) or \
            (command == 'USER' and is_ssl and not is_authenticated and not user) or \
            (command == 'PASS' and is_ssl and not is_authenticated and user) or \
            (command == 'PROT' and is_ssl and not is_authenticated and not user) or \
            (command == 'PBSZ' and is_ssl and not is_authenticated and not user) or \
            (command == 'PASV' and is_ssl and is_authenticated and not data_port) or \
            (command in {'LIST', 'STOR', 'RETR'} and is_authenticated and data_client) or \
            (command not in {'AUTH', 'USER', 'PASS',
                             'PASV', 'LIST', 'STOR', 'RETR'} and is_ssl and is_authenticated)

        return is_good

    async def main_client_loop(parent_locals):
        async for line in command_sock_recv_lines():
            command_bytes, _, arg = line.partition(b' ')
            command = command_bytes.decode('utf-8')
            logger.debug('Inc: %s', command_bytes + b' ' + arg)

            async with timeout(loop, COMMAND_TIMEOUT_SECONDS):
                if not is_good_sequence(command):
                    await command_responses.put(b'503 Bad sequence of commands.')
                    await command_responses.join()
                    await cancel_current_task()
                elif not is_implemented(parent_locals, command):
                    await command_responses.put(b'502 Command not implemented.')
                else:
                    with logged(logger, command, []):
                        await get_command_func(parent_locals, command)(arg)

    send_command_responses_task = asyncio.create_task(send_command_responses())
    await command_responses.put(b'220 Service ready for new user.')

    try:
        await main_client_loop(locals())
    finally:
        await cancel_data_tasks()
        send_command_responses_task.cancel()
        await asyncio.sleep(0)

        if ssl_sock is not None:
            sock = await ssl_unwrap_socket(loop, ssl_sock, sock)
        await shutdown_socket(loop, sock)


async def cancel_client_tasks(client_tasks):
    for child in list(client_tasks):
        child.cancel()
        await asyncio.sleep(0)


async def async_main(loop, logger, ssl_context):
    env = normalise_environment(os.environ)

    command_port = int(env['FTP_COMMAND_PORT'])
    data_ports_first = int(env['FTP_DATA_PORTS_FIRST'])
    data_ports_count = int(env['FTP_DATA_PORTS_COUNT'])
    data_ports = set(range(data_ports_first, data_ports_first + data_ports_count))

    session = aiohttp.ClientSession(loop=loop)
    credentials = get_s3_secret_access_key_credentials(
        access_key_id=env['AWS_ACCESS_KEY_ID'],
        secret_access_key=env['AWS_SECRET_ACCESS_KEY'],
    )
    bucket = get_s3_bucket(
        region=env['AWS_S3_BUCKET_REGION'],
        host=env['AWS_S3_BUCKET_HOST'],
        verify_certs=True,
        name=env['AWS_S3_BUCKET_NAME'],
    )
    s3_context = get_s3_context(session, credentials, bucket)

    users = {
        env['FTP_USER_LOGIN']: env['FTP_USER_PASSWORD'],
    }

    data_cidrs = env['FTP_DATA_CIDR_TO_DOMAINS']
    resolver = aiodns.DNSResolver(loop=loop)

    async def is_user_correct(user):
        return user in users

    async def is_password_correct(user, possible_password):
        return constant_time_compare(users[user], possible_password)

    async def get_data_ip(command_sock):
        # - Not all clients handle PASV returning a private IP or 0.0.0.0
        # - We run behind multiple balancers, with different IPs the clients
        #   connect to
        # - Because of the balancers, we don't know the original IP the client
        #   connected to,
        # - The balancers don't necessarily have a fixed IP, but they do have
        #   a fixed domain, and each are in a separate subnet
        # So, we are able to match the incoming IP against the subnet CIDRS,
        # each to "reverse engineer" the correct IP for each command
        # connection
        client_ip = ipaddress.IPv4Network(command_sock.getpeername()[0] + '/32')

        matching_domain = [
            cidr['DOMAIN']
            for cidr in data_cidrs
            if client_ip.subnet_of(ipaddress.IPv4Network(cidr['CIDR']))
        ][0]

        return ((await resolver.query(matching_domain, 'A'))[0]).host

    async def is_data_sock_ok(command_sock, data_sock):
        # We don't have the actual client IP, so we can't check that the data sock is from the same
        # IP. The best we can do is check that the data request comes from same load balancer
        # subnet
        #
        # Also, apparently PASV mode data connections should be from the client's command port + 1,
        # However, this is not observed in the clients tested, so we don't check that
        command_ip = ipaddress.IPv4Network(command_sock.getpeername()[0] + '/32')
        data_ip = ipaddress.IPv4Network(data_sock.getpeername()[0] + '/32')

        command_subnet_cidr = [
            cidr['CIDR']
            for cidr in data_cidrs
            if command_ip.subnet_of(ipaddress.IPv4Network(cidr['CIDR']))
        ]
        data_subnet_cidr = [
            cidr['CIDR']
            for cidr in data_cidrs
            if data_ip.subnet_of(ipaddress.IPv4Network(cidr['CIDR']))
        ]

        return command_subnet_cidr == data_subnet_cidr

    async def _on_client_connect(logger, loop, ssl_context, sock):
        await on_client_connect(logger, loop, ssl_context, sock, get_data_ip, data_ports,
                                is_data_sock_ok, is_user_correct, is_password_correct, s3_context)

    try:
        await server(logger, loop, ssl_context, command_port,
                     _on_client_connect, cancel_client_tasks)
    except asyncio.CancelledError:
        pass
    except BaseException:
        logger.exception('Server exception')
    finally:
        logger.debug('Server closing... Allowing tasks to cleanup...')
        await session.close()
        await asyncio.sleep(1)
        logger.debug('Server closed.')


# We have an entirely separate port for healthchecks from the NLB. Although
# this slightly defeats the purpose of healthchecks...
#
# - We're going to have some other healthcheck triggered from Pingdom,
#   checking if the server really works in terms of doing things with FTP.
# - Actually the more complex things, which are more likely to go wrong, are
#   the data ports for PASV mode, which just allowing TCP connections doesn't
#   check.
# - It can have a null logger, which doesn't log anything, and so eases
#   debugging on the real connections.
# - It means we only have to open up the healthcheck port from the subnets
#   that have the NLBs, rather the command port
#
# Maybe this isn't the best long term strategy, but ok for now.
async def healthcheck(loop, logger, ssl_context):

    async def on_healthcheck_client_connect(_, loop, __, sock):
        await shutdown_socket(loop, sock)

    healthcheck_port = int(os.environ['HEALTHCHECK_PORT'])
    ssl_context = None
    try:
        await server(logger, loop, ssl_context, healthcheck_port,
                     on_healthcheck_client_connect, cancel_client_tasks)
    except asyncio.CancelledError:
        pass


def main():
    loop = asyncio.get_event_loop()

    ssl_context = SSLContext(PROTOCOL_TLSv1_2)
    ssl_context.load_cert_chain(f'{os.environ["HOME"]}/ssl.crt',
                                keyfile=f'{os.environ["HOME"]}/ssl.key')

    healthcheck_logger = logging.getLogger('healthcheck')
    healthcheck_logger.setLevel(logging.WARNING)
    healthcheck_logger_with_context = get_logger_with_context(healthcheck_logger, 'healthcheck')
    loop.create_task(healthcheck(loop, healthcheck_logger_with_context, ssl_context))

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    logger_with_context = get_logger_with_context(logger, 'ftps3')
    main_task = loop.create_task(async_main(loop, logger_with_context, ssl_context))
    loop.add_signal_handler(signal.SIGINT, main_task.cancel)
    loop.add_signal_handler(signal.SIGTERM, main_task.cancel)

    loop.run_until_complete(main_task)

    logger_with_context.debug('Exiting.')


if __name__ == '__main__':
    main()
