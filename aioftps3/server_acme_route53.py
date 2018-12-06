import asyncio
import base64
import binascii
from collections import (
    namedtuple,
)
import hashlib
import json
import random
import re
from ssl import (
    PROTOCOL_TLSv1_2,
    SSLContext,
)

from aioftps3.server_aws import (
    aws_request,
)
from aioftps3.server_logger import (
    get_child_logger,
    logged,
)
from aioftps3.server_s3 import (
    s3_hash,
    s3_request_full,
)


AcmeContext = namedtuple('AcmeContext', [
    'session', 'directory_url',
])

Route53Context = namedtuple('Route53Context', [
    'session', 'credentials', 'host', 'region', 'verify_certs', 'zone_id'
])

FilePath = namedtuple('FilePath', [
    'remote', 'local',
])


async def acme_ssl_context_manager(logger, s3_context, route_53_context, acme_context,
                                   get_domain, domains, local_path):
    ssl_contexts = {}

    def get_context(sock):
        return ssl_contexts[get_domain(sock)]

    def _load_context(logger, domain, ssl_key, ssl_crt):
        with logged(logger, 'Loading context %s %s', [ssl_key.local, ssl_crt.local]):
            ssl_context = SSLContext(PROTOCOL_TLSv1_2)
            ssl_context.load_cert_chain(ssl_crt.local, keyfile=ssl_key.local)
            ssl_contexts[domain] = ssl_context

    account_key = FilePath('account.key', f'{local_path}/account.key')
    domains_paths = [
        (domain, {
            'key': FilePath(f'{domain}.key', f'{local_path}/{domain}.key'),
            'csr': FilePath(f'{domain}.csr', f'{local_path}/{domain}.csr'),
            'crt': FilePath(f'{domain}.crt', f'{local_path}/{domain}.crt'),
        }) for domain in domains
    ]
    await _fetch_acme_objects(logger, s3_context, account_key, domains_paths)

    async def renew_if_necessary(renew_logger):
        for domain, paths in domains_paths:
            if await _should_renew(renew_logger, paths['crt'].local):
                await _renew(renew_logger, s3_context, route_53_context, acme_context,
                             account_key, domain, paths['csr'], paths['crt'])
            _load_context(renew_logger, domain, paths['key'], paths['crt'])

    await renew_if_necessary(logger)
    return _random_cron(logger, renew_if_necessary), get_context


async def _fetch_acme_objects(logger, s3_context, account_key, domains_paths):
    with logged(logger, 'Fetching keys and certs from S3', []):
        response = await _get_object_and_save(
            logger, s3_context, account_key.remote, account_key.local)
        response.raise_for_status()

        for _, paths in domains_paths:
            key = paths['key']
            response = await _get_object_and_save(logger, s3_context, key.remote, key.local)
            response.raise_for_status()
            csr = paths['csr']
            response = await _get_object_and_save(logger, s3_context, csr.remote, csr.local)
            response.raise_for_status()

            # No raise_for_status: we might not yet have generated a certificate
            crt = csr = paths['crt']
            await _get_object_and_save(logger, s3_context, crt.remote, crt.local)


async def _renew(logger, s3_context, route_53_context, acme_context, account_key,
                 domain, ssl_csr, ssl_crt):
    with logged(logger, 'Renewing', []):

        jwk, jwk_thumbprint = await _parse_account_key(logger, account_key.local)
        directory = await _directory(logger, acme_context)

        account_url = await _account_url(
            logger, acme_context, directory, account_key.local, jwk)

        order, order_location = await _order_dns(
            logger, acme_context, directory, account_key.local, account_url, [domain])

        challenge = await _dns_challenge(
            logger, acme_context, order)

        txt_contents = _txt_contents(challenge['token'], jwk_thumbprint)
        txt_domain = f'_acme-challenge.{domain}'
        await _route_53_upsert_txt(
            logger, route_53_context, txt_contents, txt_domain)

        await _inform_can_be_validated(
            logger, acme_context, directory, account_key.local, account_url, challenge)
        await _confirm_validated(
            logger, acme_context, order)
        await _finalise(
            logger, acme_context, directory, account_key.local, account_url, order, ssl_csr)

        cert_url = await _certificate_url(
            logger, acme_context, order_location)
        cert_data = await _download_certificate(
            logger, acme_context, cert_url)

        await _put_object_and_save(
            logger, s3_context, ssl_crt.remote, ssl_crt.local, cert_data)


async def _get_object_and_save(logger, s3_context, key, local_path):
    response, data = await s3_request_full(
        logger, s3_context, 'GET', f'/{key}', {}, {}, b'', s3_hash(b''))

    with open(f'{local_path}', 'wb') as file:
        file.write(data)

    return response


async def _put_object_and_save(logger, s3_context, key, local_path, data):
    with logged(logger, 'Saving to S3 %s %s', [key, local_path]):
        with open(f'{local_path}', 'wb') as file:
            file.write(data)

        response, _ = await s3_request_full(logger, s3_context, 'PUT', f'/{key}',
                                            {}, {}, data, s3_hash(data))
        response.raise_for_status()


async def _should_renew(logger, path):
    with logged(logger, 'Determining whether to renew', []):
        _, _, code = await _subprocess(
            logger, ['openssl', 'x509', '-checkend', str(60 * 60 * 24 * 10), '-in', path],
            input_bytes=None)
    return bool(code)


async def _directory(logger, context):
    with logged(logger, 'Fetching directory', []):
        _, body = await _acme_request(logger, context, 'GET', context.directory_url, b'')
        return json.loads(body)


async def _account_url(logger, context, directory, account_key_path, jwk):
    with logged(logger, 'Finding account location', []):
        create_account_payload = to_json({'termsOfServiceAgreed': True})
        response, _ = await _signed_acme_request(
            logger, context, directory, account_key_path, {'jwk': jwk},
            'POST', directory['newAccount'], create_account_payload,
        )
        return response.headers['Location']


async def _order_dns(logger, context, directory, account_key_path, account_url, domains):
    with logged(logger, 'Creating order for %s', [domains]):
        order_payload = to_json({
            'identifiers': [{'type': 'dns', 'value': domain} for domain in domains],
        })
        response, body = await _signed_acme_request(
            logger, context, directory, account_key_path, {'kid': account_url},
            'POST', directory['newOrder'], order_payload,
        )
        return json.loads(body), response.headers['Location']


async def _dns_challenge(logger, context, order):
    with logged(logger, 'Fetching challenges', []):
        # Only support a single authorization for now, with a single dns challenge
        url = order['authorizations'][0]
        _, body = await _acme_request(logger, context, 'GET', url, b'')
        challenge = [
            challenge for challenge in
            json.loads(body)['challenges']
            if challenge['type'] == 'dns-01'
        ][0]
        return challenge


def _txt_contents(token, jwk_thumbprint):
    auth = f'{token}.{jwk_thumbprint}'
    auth_sha256_b64 = b64_encode(hashlib.sha256(auth.encode('utf8')).digest())
    return f'"{auth_sha256_b64}"'


async def _inform_can_be_validated(logger, context, directory, account_key_path, account_url,
                                   challenge):
    with logged(logger, 'Informing challenge can be validated', []):
        _, _ = await _signed_acme_request(
            logger, context, directory, account_key_path, {'kid': account_url},
            'POST', challenge['url'], to_json({}),
        )


async def _confirm_validated(logger, context, order):
    with logged(logger, 'Confirming challenge validated', []):
        url = order['authorizations'][0]
        status = 'pending'
        max_checks = 20
        num_checks = 0
        interval = 5
        while status == 'pending' and num_checks < max_checks:
            await asyncio.sleep(interval)

            _, body = await _acme_request(logger, context, 'GET', url, b'')
            status = json.loads(body)['status']
            num_checks += 1

        if status != 'valid':
            logger.debug(body)
            raise Exception(f'ACME did not verify the challenge: status is {status}')


async def _finalise(logger, context, directory, account_key_path, account_url, order, ssl_csr):
    with logged(logger, 'Finalising', []):
        csr_der = await _subprocess_stdout(
            logger, ['openssl', 'req', '-in', ssl_csr.local, '-outform', 'DER'], input_bytes=None)

        payload = {'csr': b64_encode(csr_der)}
        _, _ = await _signed_acme_request(
            logger, context, directory, account_key_path, {'kid': account_url},
            'POST', order['finalize'], to_json(payload),
        )


async def _certificate_url(logger, context, order_location):
    with logged(logger, 'Fetching certificate URL', []):
        status = 'pending'
        max_checks = 20
        num_checks = 0
        interval = 5
        while status in ['pending', 'processing'] and num_checks < max_checks:
            await asyncio.sleep(interval)

            _, body = await _acme_request(logger, context, 'GET', order_location, b'')
            order = json.loads(body)
            status = order['status']
            num_checks += 1

        if status != 'valid':
            raise Exception('Order not valid')

        return order['certificate']


async def _download_certificate(logger, context, cert_location):
    with logged(logger, 'Downloading certificate', []):
        _, body = await _acme_request(logger, context, 'GET', cert_location, b'')
        return body


async def _parse_account_key(logger, path):
    with logged(logger, 'Parsing account key', []):
        account_key_text = (await _subprocess_stdout(
            logger, ['openssl', 'rsa', '-in', path, '-noout', '-text'], input_bytes=None
        )).decode('utf8')

        pub_pattern = r'modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)'
        pub_hex, pub_exp = re.search(pub_pattern, account_key_text, re.MULTILINE).groups()

        pub_exp_int = int(pub_exp)
        pub_exp_hex = f'{pub_exp_int:x}'
        pub_exp_hex_even = ('0' * (len(pub_exp_hex) % 2)) + pub_exp_hex
        pub_exp_binary = hex_to_binary(pub_exp_hex_even)
        pub_exp_b64 = b64_encode(pub_exp_binary)

        pub_hex_concat = re.sub(r'[\s:]', '', pub_hex).encode('utf-8')
        pub_binary = hex_to_binary(pub_hex_concat)
        pub_hex_b64 = b64_encode(pub_binary)

        jwk = {
            'kty': 'RSA',
            'e': pub_exp_b64,
            'n': pub_hex_b64,
        }
        jwk_thumbprint = b64_encode(hashlib.sha256(to_json(jwk)).digest())

    return jwk, jwk_thumbprint


async def _signed_acme_request(logger, context, directory, account_key_path, protected_headers,
                               method, url, payload):

    async def get_nonce():
        response, _ = await _acme_request(logger, context, 'GET', directory['newNonce'], b'')
        return response.headers['Replay-Nonce']

    payload_b64 = b64_encode(payload)

    protected_nonce = await get_nonce()
    protected = {'url': url, 'alg': 'RS256', 'nonce': protected_nonce, **protected_headers}
    protected_b64 = b64_encode(to_json(protected))

    to_sign = f'{protected_b64}.{payload_b64}'.encode('utf8')

    signature = await _subprocess_stdout(
        logger, ['openssl', 'dgst', '-sha256', '-sign', account_key_path], input_bytes=to_sign)
    signed_payload = to_json({
        'payload': payload_b64,
        'protected': protected_b64,
        'signature': b64_encode(signature),
    })
    return await _acme_request(logger, context, method, url, signed_payload)


async def _acme_request(logger, context, method, url, data):
    headers = {'Content-Type': 'application/jose+json'}
    with logged(logger, 'ACME request %s %s', [method, url]):
        async with context.session.request(method, url, headers=headers, data=data) as response:
            response_body = await response.read()
            response.raise_for_status()
            return response, response_body


async def _route_53_upsert_txt(logger, context, txt_contents, txt_domain):
    with logged(logger, 'Creating txt record %s %s', [txt_domain, txt_contents]):
        namespace = 'https://route53.amazonaws.com/doc/2013-04-01/'
        upsert_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<ChangeResourceRecordSetsRequest xmlns="{namespace}">'
            '<ChangeBatch><Changes><Change>'
            '<Action>UPSERT</Action>'
            '<ResourceRecordSet>'
            f'<Name>{txt_domain}</Name>'
            '<ResourceRecords><ResourceRecord>'
            f'<Value>{txt_contents}</Value>'
            '</ResourceRecord></ResourceRecords>'
            '<TTL>60</TTL>'
            '<Type>TXT</Type>'
            '</ResourceRecordSet>'
            '</Change></Changes></ChangeBatch>'
            '</ChangeResourceRecordSetsRequest>'
        ).encode('utf-8')

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


async def _subprocess_stdout(logger, args, input_bytes):
    stdout, stderr, returncode = await _subprocess(logger, args, input_bytes)
    if bool(returncode):
        raise Exception('Subprocess error: {} {}'.format(str(returncode), stderr.encode('utf-8')))
    return stdout


async def _subprocess(logger, args, input_bytes):
    with logged(logger, 'Subprocess: %s', [args]):
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate(input=input_bytes)
        return stdout, stderr, proc.returncode


async def _random_cron(logger, func):
    cron_logger = get_child_logger(logger, 'cron')
    while True:
        await asyncio.sleep(60 * 60 * (1 + random.random()))
        try:
            await func(cron_logger)
        except asyncio.CancelledError:
            raise
        except BaseException:
            pass


def b64_encode(binary):
    return base64.urlsafe_b64encode(binary).decode('utf8').replace('=', '')


def hex_to_binary(hex_string):
    return binascii.unhexlify(hex_string)


def to_json(dictionary):
    return json.dumps(dictionary, sort_keys=True, separators=(',', ':')).encode('utf8')
