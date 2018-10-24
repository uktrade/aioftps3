import logging
import ssl
import os
import sys

import asyncio
import aioftp


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.load_cert_chain(f'{os.environ["HOME"]}/ssl.crt', keyfile=f'{os.environ["HOME"]}/ssl.key')

loop = asyncio.get_event_loop()
server = aioftp.Server(ssl=context)
loop.run_until_complete(server.start('0.0.0.0', 8021))

try:
    loop.run_forever()
except KeyboardInterrupt:
    loop.run_until_complete(server.close())
    loop.close()
