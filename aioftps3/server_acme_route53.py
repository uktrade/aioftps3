from ssl import (
    PROTOCOL_TLSv1_2,
    SSLContext,
)

from aioftps3.server_s3 import (
    s3_hash,
    s3_request_full,
)


def ssl_context_manager(logger):
    ssl_context = None

    def get_context():
        return ssl_context

    async def init_context(local_path, context):
        nonlocal ssl_context

        key_response, key_data = await s3_request_full(logger, context, 'GET', '/account.key',
                                                       {}, {}, b'', s3_hash(b''))
        key_response.raise_for_status()

        key_response, key_data = await s3_request_full(logger, context, 'GET', '/ssl.key', {}, {},
                                                       b'', s3_hash(b''))
        key_response.raise_for_status()

        cert_response, cert_data = await s3_request_full(logger, context, 'GET', '/ssl.crt',
                                                         {}, {}, b'', s3_hash(b''))
        cert_response.raise_for_status()

        cert_path = f'{local_path}/ssl.crt'
        with open(cert_path, 'wb') as cert_file:
            cert_file.write(cert_data)

        key_path = f'{local_path}/ssl.key'
        with open(key_path, 'wb') as key_file:
            key_file.write(key_data)

        ssl_context = SSLContext(PROTOCOL_TLSv1_2)
        ssl_context.load_cert_chain(cert_path, keyfile=key_path)

    async def refresh_cron():
        pass

    return init_context, get_context, refresh_cron
