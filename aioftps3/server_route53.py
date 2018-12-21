import asyncio
from collections import (
    namedtuple,
)
import hashlib
import re

from aioftps3.server_logger import (
    logged,
)
from aioftps3.server_aws import (
    aws_request,
)


Route53Context = namedtuple('Route53Context', [
    'session', 'credentials', 'host', 'region', 'verify_certs', 'zone_id'
])


async def route_53_upsert_rrset(logger, context, upsert_payload):
    with logged(logger, 'Upserting', []):
        upsert_path = f'/2013-04-01/hostedzone/{context.zone_id}/rrset/'
        upsert_body = await _route_53_request(logger, context, 'POST', upsert_path, upsert_payload)
        change_id = re.search(b'<Id>([^<]+)</Id>', upsert_body)[1].decode('utf-8')
        status = b'PENDING'
        change_path = f'/2013-04-01{change_id}'

        max_checks = 20
        num_checks = 0
        interval = 5
        change_payload = b''
        while status == b'PENDING' and num_checks < max_checks:
            await asyncio.sleep(interval)
            change_body = await _route_53_request(
                logger, context, 'GET', change_path, change_payload)
            status = re.search(b'<Status>([^<]+)</Status>', change_body)[1]
            num_checks += 1

        if status == b'PENDING':
            raise Exception('Route 53 change is still pending')


async def _route_53_request(logger, context, method, path, payload):
    with logged(logger, 'Route 53 request %s %s', [method, path]):
        payload_hash = hashlib.sha256(payload).hexdigest()
        request = await aws_request(
            logger, context.session, 'route53', context.region, context.host, context.verify_certs,
            context.credentials, method, path, {}, {}, payload, payload_hash)
        async with request as response:
            body = await response.read()
            response.raise_for_status()
        return body
