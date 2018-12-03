from ssl import (
    PROTOCOL_TLSv1_2,
    SSLContext,
)


def ssl_context_manager(cert_path, private_key_path):
    ssl_context = SSLContext(PROTOCOL_TLSv1_2)
    ssl_context.load_cert_chain(cert_path, keyfile=private_key_path)

    def get_context():
        return ssl_context

    async def refresh_cron():
        pass

    return get_context, refresh_cron
