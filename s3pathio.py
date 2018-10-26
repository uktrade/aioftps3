from collections import (
    namedtuple,
)
from datetime import datetime
import hashlib
import hmac
from pathlib import PurePosixPath
import urllib
import xml.etree.ElementTree as ET

from aioftp.pathio import (
    universal_exception,
)

REG_MODE = 0o10000  # stat.S_IFREG
DIR_MODE = 0o40000  # stat.S_IFDIR

# The S3 console uses '/' as both the folder separator for
# navigation, and as the suffix for objects created when
# you create a folder, so we do exacty the same here
S3_DIR_SUFFIX = '/'

Stat = namedtuple(
    'Stat',
    ['st_size', 'st_mtime', 'st_ctime', 'st_nlink', 'st_mode'],
)

AwsCredentials = namedtuple('AwsCredentials', [
    'access_key_id', 'secret_access_key', 'pre_auth_headers',
])

AwsS3Bucket = namedtuple('AwsS3Bucket', [
    'region', 'host', 'name',
])


class S3Path(PurePosixPath):
    ''' The purpose of this class is to be able to integrate with
    code in aioftp that expects a Path instance, but be able to
    attach more data that is returned from S3 List Objects which
    we access from S3PathIO
    '''

    def __new__(cls, *args, stat):
        self = super().__new__(cls, *args)
        self.stat = stat
        return self


def s3_path_io_factory(session, credentials, bucket):

    # The aioftp way of configuring the path with a "nursery" doesn't
    # seem that configurable in terms of doing things per instance,
    # so make our own that effectively bypasses it
    def factory(*_, **__):
        return S3PathIO(session, credentials, bucket)

    return factory


def s3_path_io_secret_access_key_credentials(access_key_id, secret_access_key):

    async def get():
        return AwsCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            pre_auth_headers={},
        )

    return get


def s3_path_io_bucket(region, host, name):
    return AwsS3Bucket(
        region=region,
        host=host,
        name=name,
    )


class S3PathIO():

    def __init__(self, session, credentials, bucket):
        self.session = session
        self.credentials = credentials
        self.bucket = bucket

        # The aioftp's mechanism for state doesn't seem that
        # configurable per instance, so we don't use it. However,
        # it does expect a member called state
        self.state = None

    @universal_exception
    async def exists(self, path):
        return await self.is_file(path) or await self.is_dir(path)

    @universal_exception
    async def is_dir(self, path):
        result = \
            True if isinstance(path, S3Path) and path.stat.st_mode & DIR_MODE else \
            True if path == PurePosixPath('.') else \
            await _dir_exists(self.session, self.credentials, self.bucket, path)
        return result

    @universal_exception
    async def is_file(self, path):
        result = \
            True if isinstance(path, S3Path) and path.stat.st_mode & REG_MODE else \
            False if path == PurePosixPath('.') else \
            await _file_exists(self.session, self.credentials, self.bucket, path)
        return result

    @universal_exception
    async def mkdir(self, path, *, parents=False, exist_ok=False):
        raise NotImplementedError

    @universal_exception
    async def rmdir(self, path):
        raise NotImplementedError

    @universal_exception
    async def unlink(self, path):
        raise NotImplementedError

    def list(self, path):
        return _list(self.session, self.credentials, self.bucket, path)

    @universal_exception
    async def stat(self, path):
        return path.stat

    def open(self, path, mode):
        return OPENERS[mode](self.session, self.credentials, self.bucket, path)

    @universal_exception
    async def rename(self, source, destination):
        raise NotImplementedError


async def _file_exists(session, credentials, bucket, path):
    key = path.as_posix()
    response, _ = await _make_s3_request(session, credentials, bucket,
                                         'HEAD', '/' + key, {}, {}, b'')
    return response.status == 200


async def _dir_exists(session, credentials, bucket, path):
    key = path.as_posix()
    response, _ = await _make_s3_request(session, credentials, bucket,
                                         'HEAD', '/' + key + S3_DIR_SUFFIX, {}, {}, b'')
    return response.status == 200


async def _list(session, creds, bucket, path):
    key_prefix = \
        '' if path == PurePosixPath('.') else \
        path.as_posix() + S3_DIR_SUFFIX

    for child_path in await _list_immediate_child_paths(session, creds, bucket, key_prefix):
        yield child_path


def _open_wb(session, creds, bucket, path):

    chunks = []

    def append_chunk(chunk):
        chunks.append(chunk)

    async def put_data():
        payload = b''.join(chunks)
        key = path.as_posix()
        response, _ = await _make_s3_request(session, creds, bucket,
                                             'PUT', '/' + key, {}, {}, payload)
        response.raise_for_status()

    class WritableFile():

        async def __aenter__(self):
            pass

        async def __aexit__(self, exc_type, exc, traceback):
            if exc_type is not None:
                return
            await put_data()

        @staticmethod
        async def write(chunk):
            append_chunk(chunk)

    return WritableFile()


def _open_rb(session, creds, bucket, path):

    data = b''

    async def get_data():
        nonlocal data
        key = path.as_posix()
        response, body = await _make_s3_request(session, creds, bucket,
                                                'GET', '/' + key, {}, {}, b'')
        response.raise_for_status()
        data = body

    async def iter_data(count):
        for i in range(0, len(data), count):
            yield data[i:i+count]

    class ReadableFile():

        async def __aenter__(self):
            return get_data()

        async def __aexit__(self, exc_type, exc, traceback):
            pass

        @staticmethod
        def iter_by_block(count):
            return iter_data(count)

    return ReadableFile()


async def _list_immediate_child_paths(session, creds, bucket, key_prefix):
    return await _list_paths(session, creds, bucket, key_prefix, S3_DIR_SUFFIX)


async def _list_paths(session, creds, bucket, key_prefix, delimeter):
    epoch = datetime.utcfromtimestamp(0)
    common_query = {
        'max-keys': '1000',
        'list-type': '2',
    }

    async def _list_first_page():
        query = {
            **common_query,
            'delimiter': delimeter,
            'prefix': key_prefix,
        }
        _, body = await _make_s3_request(session, creds, bucket, 'GET', '/', query, {}, b'')
        return _parse_list_response(body)

    async def _list_later_page(token):
        query = {
            **common_query,
            'continuation-token': token,
        }
        _, body = await _make_s3_request(session, creds, bucket, 'GET', '/', query, {}, b'')
        return _parse_list_response(body)

    def _first_child_text(element, tag):
        for child in element:
            if child.tag == tag:
                return child.text
        return None

    def _parse_list_response(body):
        namespace = '{http://s3.amazonaws.com/doc/2006-03-01/}'
        root = ET.fromstring(body)
        next_token = ''
        paths = []
        for element in root:
            if element.tag == f'{namespace}Contents':
                key = _first_child_text(element, f'{namespace}Key')
                if key[-1] == S3_DIR_SUFFIX:
                    continue

                last_modified_str = _first_child_text(element, f'{namespace}LastModified')
                last_modified_datetime = datetime.strptime(
                    last_modified_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                last_modified_since_epoch_seconds = int(
                    (last_modified_datetime - epoch).total_seconds())
                size = int(_first_child_text(element, f'{namespace}Size'))
                paths.append(S3Path(key, stat=Stat(
                    st_size=size,
                    st_mtime=last_modified_since_epoch_seconds,
                    st_ctime=last_modified_since_epoch_seconds,
                    st_nlink=1,
                    st_mode=REG_MODE,
                )))

            if element.tag == f'{namespace}CommonPrefixes':
                # Prefixes end in '/', which we strip off
                key_prefix = _first_child_text(element, f'{namespace}Prefix')[:-1]
                paths.append(S3Path(key_prefix, stat=Stat(
                    # Not completely sure what size should be for a directory
                    st_size=0,
                    # Can't quite work out an efficient way of working out
                    # any sort of meaningful modification/creation time for a
                    # directory
                    st_mtime=0,
                    st_ctime=0,
                    st_nlink=1,
                    st_mode=DIR_MODE,
                )))

            if element.tag == f'{namespace}NextContinuationToken':
                next_token = element.text

        return (next_token, paths)

    token, paths = await _list_first_page()
    while token:
        token, paths_page = await _list_later_page(token)
        paths.extend(paths_page)

    return paths


async def _make_s3_request(session, credentials, bucket,
                           method, path, query, api_pre_auth_headers, payload):

    service = 's3'
    creds = await credentials()
    pre_auth_headers = {
        **api_pre_auth_headers,
        **creds.pre_auth_headers,
    }
    full_path = f'/{bucket.name}{path}'
    headers = _aws_sig_v4_headers(
        creds.access_key_id, creds.secret_access_key, pre_auth_headers,
        service, bucket.region, bucket.host, method, full_path, query, payload,
    )

    querystring = urllib.parse.urlencode(query, safe='~', quote_via=urllib.parse.quote)
    encoded_path = urllib.parse.quote(full_path, safe='/~')
    url = f'https://{bucket.host}{encoded_path}' + (('?' + querystring) if querystring else '')

    async with session.request(method, url, headers=headers, data=payload) as result:
        return result, await result.read()


def _aws_sig_v4_headers(access_key_id, secret_access_key, pre_auth_headers,
                        service, region, host, method, path, query, payload):
    algorithm = 'AWS4-HMAC-SHA256'

    now = datetime.utcnow()
    amzdate = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')
    payload_hash = hashlib.sha256(payload).hexdigest()
    credential_scope = f'{datestamp}/{region}/{service}/aws4_request'

    pre_auth_headers_lower = {
        header_key.lower(): ' '.join(header_value.split())
        for header_key, header_value in pre_auth_headers.items()
    }
    required_headers = {
        'host': host,
        'x-amz-content-sha256': payload_hash,
        'x-amz-date': amzdate,
    }
    headers = {**pre_auth_headers_lower, **required_headers}
    header_keys = sorted(headers.keys())
    signed_headers = ';'.join(header_keys)

    def signature():
        def canonical_request():
            canonical_uri = urllib.parse.quote(path, safe='/~')
            quoted_query = sorted(
                (urllib.parse.quote(key, safe='~'), urllib.parse.quote(value, safe='~'))
                for key, value in query.items()
            )
            canonical_querystring = '&'.join(f'{key}={value}' for key, value in quoted_query)
            canonical_headers = ''.join(f'{key}:{headers[key]}\n' for key in header_keys)

            return f'{method}\n{canonical_uri}\n{canonical_querystring}\n' + \
                   f'{canonical_headers}\n{signed_headers}\n{payload_hash}'

        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        string_to_sign = f'{algorithm}\n{amzdate}\n{credential_scope}\n' + \
                         hashlib.sha256(canonical_request().encode('utf-8')).hexdigest()

        date_key = sign(('AWS4' + secret_access_key).encode('utf-8'), datestamp)
        region_key = sign(date_key, region)
        service_key = sign(region_key, service)
        request_key = sign(service_key, 'aws4_request')
        return sign(request_key, string_to_sign).hex()

    return {
        **pre_auth_headers,
        'x-amz-date': amzdate,
        'x-amz-content-sha256': payload_hash,
        'Authorization': f'{algorithm} Credential={access_key_id}/{credential_scope}, '
                         f'SignedHeaders={signed_headers}, Signature=' + signature(),
    }


OPENERS = {
    'wb': _open_wb,
    'rb': _open_rb,
}
