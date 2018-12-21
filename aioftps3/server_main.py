import asyncio
import base64
import hashlib
import ipaddress
import logging
import os
import signal
import sys

import aiodns
import aiohttp

from aioftps3.server import (
    on_client_connect,
)
from aioftps3.server_route53 import (
    Route53Context,
    route_53_upsert_task_private_ip,
)
from aioftps3.server_acme_route53 import (
    acme_ssl_context_manager,
    AcmeContext,
)
from aioftps3.server_logger import (
    get_child_logger,
    get_logger_with_context,
)
from aioftps3.server_s3 import (
    get_s3_bucket,
    get_s3_context,
    get_ecs_role_credentials,
    get_secret_access_key_credentials,
)
from aioftps3.server_socket import (
    server,
    shutdown_socket,
)
from aioftps3.server_utils import (
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


async def async_main(loop, environ, logger, listening):
    env = normalise_environment(environ)
    logger_with_context = get_logger_with_context(logger, 'ftps3')

    command_port = int(env['FTP_COMMAND_PORT'])
    data_ports_first = int(env['FTP_DATA_PORTS_FIRST'])
    data_ports_count = int(env['FTP_DATA_PORTS_COUNT'])
    data_ports = set(range(data_ports_first, data_ports_first + data_ports_count))

    session = aiohttp.ClientSession(loop=loop)

    auth_mechanisms = {
        'secret_access_key': lambda: get_secret_access_key_credentials(
            access_key_id=env['AWS_ACCESS_KEY_ID'],
            secret_access_key=env['AWS_SECRET_ACCESS_KEY'],
        ),
        'ecs_role': lambda: get_ecs_role_credentials(
            url='http://169.254.170.2' + env['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'],
        ),
    }
    credentials = auth_mechanisms[env['AWS_AUTH_MECHANISM']]()
    bucket = get_s3_bucket(
        region=env['AWS_S3_BUCKET']['REGION'],
        host=env['AWS_S3_BUCKET']['HOST'],
        verify_certs=env['AWS_S3_BUCKET']['VERIFY_CERTS'] == 'true',
        name=env['AWS_S3_BUCKET']['NAME'],
        dir_suffix=env['AWS_S3_BUCKET']['DIR_SUFFIX'],
    )
    s3_context = get_s3_context(session, credentials, bucket)

    users = {
        user['LOGIN']: (base64.b64decode(user['PASSWORD_HASHED']), user['PASSWORD_SALT'])
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

        hashed_correct_password, salt = users[user]
        hashed_possible_password = hashlib.pbkdf2_hmac(
            'sha256', possible_password.encode('ascii'), salt.encode('ascii'), iterations=1000000)

        if constant_time_compare(hashed_correct_password, hashed_possible_password):
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
        return ((await resolver.query(get_domain(command_sock), 'A'))[0]).host

    def get_domain(sock):
        client_ip = ipaddress.IPv4Network(sock.getpeername()[0] + '/32')

        return [
            cidr['DOMAIN']
            for cidr in data_cidrs
            if client_ip.subnet_of(ipaddress.IPv4Network(cidr['CIDR']))
        ][0]

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

    route53_logger = get_child_logger(logger_with_context, 'route53')
    route53_context = Route53Context(
        session=session,
        credentials=credentials,
        host=env['AWS_ROUTE_53']['HOST'],
        region=env['AWS_ROUTE_53']['REGION'],
        verify_certs=env['AWS_ROUTE_53']['VERIFY_CERTS'] == 'true',
        zone_id=env['AWS_ROUTE_53']['ZONE_ID'],
    )
    metadata_url = env['ECS_CONTAINER_METADATA_URI'] + '/task'
    await route_53_upsert_task_private_ip(route53_logger, route53_context, metadata_url)

    acme_bucket = get_s3_bucket(
        region=env['AWS_S3_ACME_BUCKET']['REGION'],
        host=env['AWS_S3_ACME_BUCKET']['HOST'],
        verify_certs=env['AWS_S3_ACME_BUCKET']['VERIFY_CERTS'] == 'true',
        name=env['AWS_S3_ACME_BUCKET']['NAME'],
        dir_suffix=None,
    )
    acme_s3_context = get_s3_context(session, credentials, acme_bucket)
    acme_logger = get_child_logger(logger_with_context, 'acme')
    acme_context = AcmeContext(session=session, directory_url=env['ACME_DIRECTORY'])
    domains = [data_cidr['DOMAIN'] for data_cidr in data_cidrs]
    renew_cron, get_ssl_context = await acme_ssl_context_manager(
        acme_logger, acme_s3_context, route53_context, acme_context, get_domain,
        domains, env['ACME_PATH'])

    renew_cron_task = loop.create_task(renew_cron)

    def on_listening(_):
        listening.set()

    async def _on_client_connect(logger, loop, get_ssl_context, sock):
        await on_client_connect(logger, loop, get_ssl_context, sock, get_data_ip, data_ports,
                                is_data_sock_ok, is_user_correct, is_password_correct, s3_context)

    try:
        await server(logger_with_context, loop, get_ssl_context, command_port, on_listening,
                     _on_client_connect, cancel_client_tasks)
    except asyncio.CancelledError:
        renew_cron_task.cancel()
    except BaseException:
        logger_with_context.exception('Server exception')
    finally:
        logger_with_context.debug('Server closing... Allowing tasks to cleanup...')
        await session.close()
        await asyncio.sleep(1)
        logger_with_context.debug('Server closed.')


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
async def healthcheck(loop, logger):
    logger_with_context = get_logger_with_context(logger, 'healthcheck')

    def on_listening(_):
        pass

    async def on_healthcheck_client_connect(_, loop, __, sock):
        await shutdown_socket(loop, sock)

    healthcheck_port = int(os.environ['HEALTHCHECK_PORT'])

    def get_ssl_context(_):
        return None

    try:
        await server(logger_with_context, loop, get_ssl_context, healthcheck_port, on_listening,
                     on_healthcheck_client_connect, cancel_client_tasks)
    except asyncio.CancelledError:
        pass


def main():
    loop = asyncio.get_event_loop()

    healthcheck_logger = logging.getLogger('healthcheck')
    healthcheck_logger.setLevel(logging.WARNING)
    loop.create_task(healthcheck(loop, healthcheck_logger))

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    listening = asyncio.Event()
    main_task = loop.create_task(async_main(loop, os.environ, logger, listening))
    loop.add_signal_handler(signal.SIGINT, main_task.cancel)
    loop.add_signal_handler(signal.SIGTERM, main_task.cancel)

    loop.run_until_complete(main_task)

    logger.debug('Exiting.')


if __name__ == '__main__':
    main()
