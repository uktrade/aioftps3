from ssl import (
    PROTOCOL_TLSv1_2,
    SSLContext,
)


def ssl_context_manager():
    ssl_context = None

    def get_context():
        return ssl_context

    async def init_context(cert_path, private_key_path):
        nonlocal ssl_context
        ssl_context = SSLContext(PROTOCOL_TLSv1_2)
        ssl_context.load_cert_chain(cert_path, keyfile=private_key_path)

    async def refresh_cron():
        pass

    return init_context, get_context, refresh_cron
