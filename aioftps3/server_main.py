import asyncio
import ipaddress
import logging
import os
import signal
from ssl import (
    PROTOCOL_TLSv1_2,
    SSLContext,
)
import sys

import aiodns
import aiohttp

from server import (
    on_client_connect,
)
from server_logger import (
    get_logger_with_context,
)
from server_s3 import (
    get_s3_bucket,
    get_s3_context,
    get_s3_ecs_role_credentials,
    get_s3_secret_access_key_credentials,
)
from server_socket import (
    server,
    shutdown_socket,
)
from server_utils import (
    ExpiringDict,
    ExpiringSet,
    constant_time_compare,
    normalise_environment,
)


# The window of time when failed logins are counted
LOGIN_FAILED_ATTEMPTS_WINDOW_SECONDS = 60 * 60 * 24

# How many failed attempts in the window
LOGIN_FAILED_ATTEMPTS_MAX_BEFORE_LOGOUT = 5

# How long a lockout will last
LOGIN_LOCKOUT_SECONDS = 60 * 30


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

    auth_mechanisms = {
        'secret_access_key': lambda: get_s3_secret_access_key_credentials(
            access_key_id=env['AWS_ACCESS_KEY_ID'],
            secret_access_key=env['AWS_SECRET_ACCESS_KEY'],
        ),
        'ecs_role': lambda: get_s3_ecs_role_credentials(
            url='http://169.254.170.2/' + env['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'],
        ),
    }
    credentials = auth_mechanisms[env['AWS_AUTH_MECHANISM']]()
    bucket = get_s3_bucket(
        region=env['AWS_S3_BUCKET_REGION'],
        host=env['AWS_S3_BUCKET_HOST'],
        verify_certs=True,
        name=env['AWS_S3_BUCKET_NAME'],
    )
    s3_context = get_s3_context(session, credentials, bucket)

    users = {
        user['LOGIN']: user['PASSWORD']
        for user in env['FTP_USERS']
    }

    data_cidrs = env['FTP_DATA_CIDR_TO_DOMAINS']
    resolver = aiodns.DNSResolver(loop=loop)

    num_failed_logins = ExpiringDict(loop, LOGIN_FAILED_ATTEMPTS_WINDOW_SECONDS)
    locked_out_users = ExpiringSet(loop, LOGIN_LOCKOUT_SECONDS)

    async def is_user_correct(user):
        return user in users

    async def is_password_correct(logger, user, possible_password):
        if user in locked_out_users:
            logger.debug('%s: Locked out user attempting login.', user)
            return False

        if constant_time_compare(users[user], possible_password):
            logger.debug('%s: Password is correct. Allowing login.', user)
            return True

        if user not in num_failed_logins:
            num_failed_logins[user] = 1
        else:
            num_failed_logins[user] += 1

        logger.debug('%s: Failed login attempt %s', user, num_failed_logins[user])

        if num_failed_logins[user] > LOGIN_FAILED_ATTEMPTS_MAX_BEFORE_LOGOUT:
            logger.debug('%s: Too many failed login attempts in %s seconds. '
                         'Locking out for %s seconds.',
                         user, LOGIN_FAILED_ATTEMPTS_WINDOW_SECONDS, LOGIN_LOCKOUT_SECONDS)
            locked_out_users.add(user)

        return False

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

    def on_listening(_):
        pass

    async def _on_client_connect(logger, loop, ssl_context, sock):
        await on_client_connect(logger, loop, ssl_context, sock, get_data_ip, data_ports,
                                is_data_sock_ok, is_user_correct, is_password_correct, s3_context)

    try:
        await server(logger, loop, ssl_context, command_port, on_listening,
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

    def on_listening(_):
        pass

    async def on_healthcheck_client_connect(_, loop, __, sock):
        await shutdown_socket(loop, sock)

    healthcheck_port = int(os.environ['HEALTHCHECK_PORT'])
    ssl_context = None
    try:
        await server(logger, loop, ssl_context, healthcheck_port, on_listening,
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
