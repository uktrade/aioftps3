import asyncio
from collections import (
    namedtuple,
)
from contextlib import (
    AsyncExitStack,
    asynccontextmanager,
)
from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath
import re
import weakref
import xml.etree.ElementTree as ET

from fifolock import FifoLock

from aioftps3.server_aws import (
    aws_request,
)
from aioftps3.server_logger import (
    logged,
)


# This must be between 5 and 2000MB
MULTIPART_UPLOAD_MIN_BYTES = 1024 * 1024 * 25

# How long we sleep per incoming write if uploads haven't kept up
MULTIPART_UPLOAD_IF_SLOW_SLEEP_SECONDS = 1

# How many in-progress uploads per file we allow per uploading file
MULTIPART_UPLOAD_MAX_CONCURRENT_UPLOADS_PER_FILE = 3

REG_MODE = 0o10666  # stat.S_IFREG | 0o666
DIR_MODE = 0o40777  # stat.S_IFDIR | 0o777

S3_DIR_SEPARATOR = '/'


Stat = namedtuple(
    'Stat',
    ['st_size', 'st_mtime', 'st_ctime', 'st_nlink', 'st_mode'],
)

AwsCredentials = namedtuple('AwsCredentials', [
    'access_key_id', 'secret_access_key', 'pre_auth_headers',
])

S3Bucket = namedtuple('AwsS3Bucket', [
    'region', 'host', 'verify_certs', 'name', 'dir_suffix',
])

S3Context = namedtuple('Context', [
    'session', 'lock', 'credentials', 'bucket',
])

ListKey = namedtuple('ListKey', [
    'key', 'size', 'last_modified',
])

ListPrefix = namedtuple('ListPrefix', [
    'prefix',
])


class S3ListPath(PurePosixPath):

    def __new__(cls, *args, stat):
        self = super().__new__(cls, *args)
        self.stat = stat
        return self


def get_secret_access_key_credentials(access_key_id, secret_access_key):

    async def get(_, __):
        return AwsCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            pre_auth_headers={},
        )

    return get


def get_ecs_role_credentials(url):

    aws_access_key_id = None
    aws_secret_access_key = None
    token = None
    expiration = datetime(1900, 1, 1)

    async def get(logger, session):
        nonlocal aws_access_key_id
        nonlocal aws_secret_access_key
        nonlocal token
        nonlocal expiration

        now = datetime.now()

        if now > expiration:
            method = 'GET'
            with logged(logger, 'Requesting temporary credentials from %s', [url]):
                async with session.request(method, url) as response:
                    response.raise_for_status()
                    creds = json.loads(await response.read())

            aws_access_key_id = creds['AccessKeyId']
            aws_secret_access_key = creds['SecretAccessKey']
            token = creds['Token']
            expiration = datetime.strptime(creds['Expiration'], '%Y-%m-%dT%H:%M:%SZ')

        return AwsCredentials(
            access_key_id=aws_access_key_id,
            secret_access_key=aws_secret_access_key,
            pre_auth_headers={
                'x-amz-security-token': token,
            },
        )

    return get


def get_s3_bucket(region, host, verify_certs, name, dir_suffix):
    return S3Bucket(
        region=region,
        host=host,
        verify_certs=verify_certs,
        name=name,
        dir_suffix=dir_suffix,
    )


def get_s3_context(session, credentials, bucket):
    return S3Context(
        session=session,
        lock=_PathLock(),
        credentials=credentials,
        bucket=bucket,
    )


async def s3_exists(logger, context, path):
    return await _exists(logger, context, path)


async def s3_is_dir(logger, context, path):
    return await _is_dir(logger, context, path)


async def s3_is_file(logger, context, path):
    return await _is_file(logger, context, path)


async def s3_mkdir(logger, context, path):
    async with context.lock(logger, [path]):
        if await _exists(logger, context, path):
            raise Exception('{} already exists'.format(path))

        if not await _is_dir(logger, context, path.parent):
            raise Exception('{} is not a directory'.format(path.parent))

        await _mkdir(logger, context, path)


async def s3_rmdir(logger, context, path):
    async with context.lock(logger, [path]):
        if not await _is_dir(logger, context, path):
            raise Exception('{} does not exist'.format(path))

        return await _rmdir(logger, context, path)


async def s3_delete(logger, context, path):
    async with context.lock(logger, [path]):
        if not await _is_file(logger, context, path):
            raise Exception('{} does not exist'.format(path))

        return await _delete(logger, context, path)


async def s3_list(logger, context, path):
    # We allow lists to see non-consistent changes: renames or deletes
    # of folders with lots of files could be taking a while, and nothing
    # too horrible will happen if there is a list half way through
    if not await _is_dir(logger, context, path):
        raise Exception('{} is not a directory'.format(path))

    return _list(logger, context, path)


def s3_get(logger, context, path, chunk_size):
    return _get(logger, context, path, chunk_size)


@asynccontextmanager
async def s3_put(logger, context, path):
    async with _put(logger, context, path) as write:
        yield write


async def s3_rename(logger, context, rename_from, rename_to):
    async with context.lock(logger, [rename_from, rename_to]):
        return await _rename(logger, context, rename_from, rename_to)


def _key(path):
    key = \
        '' if path == PurePosixPath('/') else \
        path.relative_to(PurePosixPath('/')).as_posix()

    return key


def _dir_key(context, path):
    key = \
        '' if path == PurePosixPath('/') else \
        path.relative_to(PurePosixPath('/')).as_posix() + context.bucket.dir_suffix

    return key


def _dir_prefix(path):
    key = \
        '' if path == PurePosixPath('/') else \
        path.relative_to(PurePosixPath('/')).as_posix() + S3_DIR_SEPARATOR

    return key


async def _exists(logger, context, path):
    return \
        await _is_file(logger, context, path) or \
        await _is_dir(logger, context, path)


async def _is_dir(logger, context, path):
    result = \
        True if path == PurePosixPath('/') else \
        await _dir_exists(logger, context, path)
    return result


async def _is_file(logger, context, path):
    result = \
        False if path == PurePosixPath('/') else \
        await _file_exists(logger, context, path)
    return result


async def _file_exists(logger, context, path):
    response, _ = await s3_request_full(logger, context, 'HEAD', '/' + _key(path), {}, {},
                                        b'', s3_hash(b''))
    return response.status == 200


async def _dir_exists(logger, context, path):
    response, _ = await s3_request_full(logger, context, 'HEAD', '/' + _dir_key(context, path),
                                        {}, {}, b'', s3_hash(b''))
    return response.status == 200


async def _mkdir(logger, context, path):
    response, _ = await s3_request_full(logger, context, 'PUT', '/' + _dir_key(context, path),
                                        {}, {}, b'', s3_hash(b''))
    response.raise_for_status()


async def _rmdir(logger, context, path):
    keys = [key async for key in _list_descendant_keys(logger, context, _dir_prefix(path))]

    def delete_sort_key(key):
        # Delete innermost files and folders first
        dir_suffix = context.bucket.dir_suffix
        is_dir_file = 1 if key.key[-len(dir_suffix):] == dir_suffix else 0
        return (key.key.count('/'), is_dir_file, key.key)

    for key in sorted(keys, key=delete_sort_key, reverse=True):
        response, _ = await s3_request_full(logger, context, 'DELETE', '/' + key.key, {}, {},
                                            b'', s3_hash(b''))
        response.raise_for_status()


async def _rename(logger, context, rename_from, rename_to):
    # The source must exist...
    from_exists = await _exists(logger, context, rename_from)
    if not from_exists:
        raise Exception('The source file does not exist')

    # ... but the target may or may not exist
    to_exists = await _exists(logger, context, rename_to)
    logger.debug('File %s exists: %s', to_exists)

    # ... we find the list of keys to rename from/to

    source_is_dir = await _is_dir(logger, context, rename_from)
    rename_from_key = _key(rename_from)
    rename_to_key = _key(rename_to)

    def replace_key_prefix(old_key):
        return rename_to_key + old_key[len(rename_from_key):]

    from_keys = \
        [
            key.key
            async for key in _list_descendant_keys(logger, context, _dir_prefix(rename_from))
        ] if source_is_dir else \
        [rename_from_key]

    to_keys = [replace_key_prefix(key) for key in from_keys]

    renames = list(zip(from_keys, to_keys))

    # ... we copy everything first...

    def sort_key(keys):
        dir_suffix = context.bucket.dir_suffix
        is_dir_file = 1 if keys[0][-len(dir_suffix):] == dir_suffix else 0
        return (keys[0].count('/'), is_dir_file, keys[0])

    for from_key, to_key in sorted(renames, key=sort_key, reverse=True):
        headers = {
            'x-amz-copy-source': f'/{context.bucket.name}/{from_key}',
        }
        response, _ = await s3_request_full(logger, context, 'PUT', '/' + to_key, {}, headers,
                                            b'', s3_hash(b''))
        response.raise_for_status()

    # ... and then delete the originals

    for from_key, _ in sorted(renames, key=sort_key):
        response, _ = await s3_request_full(logger, context, 'DELETE', '/' + from_key, {}, {},
                                            b'', s3_hash(b''))
        response.raise_for_status()


async def _list(logger, context, path):
    async for child_path in _list_immediate_child_paths(logger, context, _dir_prefix(path)):
        yield child_path


async def _delete(logger, context, path):
    response, _ = await s3_request_full(logger, context, 'DELETE', '/' + _key(path), {}, {},
                                        b'', s3_hash(b''))
    response.raise_for_status()


@asynccontextmanager
async def _put(logger, context, path):
    upload_id = None
    part_uploads = []

    part_length = None
    part_chunks = None
    part_payload_hash = None

    async def start():
        nonlocal upload_id
        new_part_init()
        upload_id = await _multipart_upload_start(logger, context, path)

    def new_part_init():
        nonlocal part_length
        nonlocal part_chunks
        nonlocal part_payload_hash
        part_length = 0
        part_chunks = []
        part_payload_hash = hashlib.sha256()

    async def write(chunk):
        # If ingress is faster than egress, need to do something to avoid storing
        # the entire file in memory. Could have something better/fancier but in
        # our case, suspect egress to S3 will always be faster than ingress, so
        # we keep this simple and just prevent from running out of memory in case
        # it happens, but also prevent the connection from dying
        if len(part_uploads) > 2 and not part_uploads[-2].done():
            await asyncio.sleep(MULTIPART_UPLOAD_IF_SLOW_SLEEP_SECONDS)

            in_progress = [upload for upload in part_uploads if not upload.done()]
            if len(in_progress) > MULTIPART_UPLOAD_MAX_CONCURRENT_UPLOADS_PER_FILE:
                raise Exception('Too many incomplete uploads to S3')

        nonlocal part_length
        part_length += len(chunk)
        part_chunks.append(chunk)
        part_payload_hash.update(chunk)

        if part_length >= MULTIPART_UPLOAD_MIN_BYTES:
            upload_part()

    def upload_part():
        part_number = str(len(part_uploads) + 1)
        upload_coro = _multipart_upload_part(
            logger, context, path, upload_id,
            part_number, part_length, part_chunks, part_payload_hash.hexdigest())
        part_uploads.append(asyncio.create_task(upload_coro))
        new_part_init()

    async def end():
        # AWS throws an error if the multipart upload doesn't have at least one part
        # which would happen if write is never called, i.e. for an empty file
        if not part_uploads:
            await write(b'')

        if part_chunks:
            upload_part()

        indexes_and_etags = await asyncio.gather(*part_uploads)

        # Completing the upload is the only action that changes anything (apart from
        # APIs that query multipart uploads), so this all we need to wrap in a lock.
        # A bucket lifecycle policy can cleanup unfinished multipart uploads, so we
        # don't need to do it here
        async with context.lock(logger, [path]):
            if await _is_file(logger, context, path.parent):
                raise Exception('{} is not a directory'.format(path.parent))

            if not await _is_dir(logger, context, path.parent):
                raise Exception('{} does not exist'.format(path.parent))

            if await _is_dir(logger, context, path):
                raise Exception('{} is a directory'.format(path))

            # Overwrites of files are allowed, so there is no need to check if
            # the file aleady exists

            await _multipart_upload_complete(logger, context, path, upload_id, indexes_and_etags)

        new_part_init()

    await start()
    yield write
    await end()


async def _multipart_upload_start(logger, context, path):
    query = {
        'uploads': '',
    }
    response, body = await s3_request_full(logger, context, 'POST', '/' + _key(path), query, {},
                                           b'', s3_hash(b''))
    response.raise_for_status()
    return re.search(b'<UploadId>(.*)</UploadId>', body)[1].decode('utf-8')


async def _multipart_upload_part(logger, context, path, upload_id, part_number, part_length,
                                 part_chunks, part_payload_hash):
    async def aiter(iterable):  # pylint: disable=redefined-builtin
        for item in iterable:
            await asyncio.sleep(0)
            yield item

    part_payload = aiter(part_chunks)
    query = {
        'partNumber': part_number,
        'uploadId': upload_id,
    }
    headers = {'Content-Length': str(part_length)}
    response, _ = await s3_request_full(logger, context, 'PUT', '/' + _key(path), query, headers,
                                        part_payload, part_payload_hash)
    response.raise_for_status()
    part_etag = response.headers['ETag']

    return (part_number, part_etag)


async def _multipart_upload_complete(logger, context, path, upload_id, part_numbers_and_etags):

    payload = (
        '<CompleteMultipartUpload>' +
        ''.join(
            f'<Part><PartNumber>{part_number}</PartNumber><ETag>{part_etag}</ETag></Part>'
            for part_number, part_etag in part_numbers_and_etags
        ) +
        '</CompleteMultipartUpload>'
    ).encode('utf-8')
    payload_hash = s3_hash(payload)
    query = {
        'uploadId': upload_id,
    }
    response, _ = await s3_request_full(logger, context, 'POST', '/' + _key(path), query, {},
                                        payload, payload_hash)
    response.raise_for_status()


async def _get(logger, context, path, chunk_size):
    # S3 GETs are atomic, so we don't need any additional locking
    # It will either fail with a 404, or return a consistent object

    method = 'GET'
    s3_path = '/' + _key(path)
    query = {}
    with logged(logger, 'Request: %s %s %s %s', [method, context.bucket.host, s3_path, query]):
        async with await _s3_request(logger, context, method, s3_path, query, {},
                                     b'', s3_hash(b'')) as response:
            response.raise_for_status()
            async for data in response.content.iter_chunked(chunk_size):
                yield data


async def _list_immediate_child_paths(logger, context, key_prefix):
    epoch = datetime.utcfromtimestamp(0)
    dir_suffix = context.bucket.dir_suffix

    async for (prefix_page, key_page) in _list_keys(logger, context, key_prefix, S3_DIR_SEPARATOR):
        for list_prefix in prefix_page:
            yield S3ListPath(list_prefix.prefix, stat=Stat(
                # Not completely sure what size should be for a directory
                st_size=0,
                # Can't quite work out an efficient way of working out
                # any sort of meaningful modification/creation time for a
                # directory
                st_mtime=epoch,
                st_ctime=epoch,
                st_nlink=1,
                st_mode=DIR_MODE,
            ))

        for list_key in key_page:
            if list_key.key[-len(dir_suffix):] == dir_suffix:
                continue
            yield S3ListPath(list_key.key, stat=Stat(
                st_size=list_key.size,
                st_mtime=list_key.last_modified,
                st_ctime=list_key.last_modified,
                st_nlink=1,
                st_mode=REG_MODE,
            ))


async def _list_descendant_keys(logger, context, key_prefix):
    async for (_, key_page) in _list_keys(logger, context, key_prefix, ''):
        for list_key in key_page:
            yield list_key


async def _list_keys(logger, context, key_prefix, delimeter):
    common_query = {
        'max-keys': '1000',
        'list-type': '2',
        'delimiter': delimeter,
        'prefix': key_prefix,
    }

    async def _list_first_page():
        query = {
            **common_query,
        }
        response, body = await s3_request_full(logger, context, 'GET', '/', query, {},
                                               b'', s3_hash(b''))
        response.raise_for_status()
        return _parse_list_response(body)

    async def _list_later_page(token):
        query = {
            **common_query,
            'continuation-token': token,
        }
        response, body = await s3_request_full(logger, context, 'GET', '/', query, {},
                                               b'', s3_hash(b''))
        response.raise_for_status()
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
        keys = []
        prefixes = []
        for element in root:
            if element.tag == f'{namespace}Contents':
                key = _first_child_text(element, f'{namespace}Key')
                last_modified_str = _first_child_text(element, f'{namespace}LastModified')
                last_modified_datetime = datetime.strptime(
                    last_modified_str, '%Y-%m-%dT%H:%M:%S.%fZ')
                size = int(_first_child_text(element, f'{namespace}Size'))
                keys.append(ListKey(key=key, last_modified=last_modified_datetime, size=size))

            if element.tag == f'{namespace}CommonPrefixes':
                # Prefixes end in '/', which we strip off
                prefix = _first_child_text(element, f'{namespace}Prefix')[:-1]
                prefixes.append(ListPrefix(prefix=prefix))

            if element.tag == f'{namespace}NextContinuationToken':
                next_token = element.text

        return (next_token, prefixes, keys)

    token, prefixes_page, keys_page = await _list_first_page()
    yield (prefixes_page, keys_page)

    while token:
        token, prefixes_page, keys_page = await _list_later_page(token)
        yield (prefixes_page, keys_page)


def s3_hash(payload):
    return hashlib.sha256(payload).hexdigest()


async def s3_request_full(logger, context, method, path, query, api_pre_auth_headers,
                          payload, payload_hash):

    with logged(logger, 'Request: %s %s %s %s %s',
                [method, context.bucket.host, path, query, api_pre_auth_headers]):
        async with await _s3_request(logger, context, method, path, query, api_pre_auth_headers,
                                     payload, payload_hash) as result:
            return result, await result.read()


async def _s3_request(logger, context, method, path, query, api_pre_auth_headers,
                      payload, payload_hash):
    bucket = context.bucket
    return await aws_request(
        logger, context.session, 's3', bucket.region, bucket.host, bucket.verify_certs,
        context.credentials, method, f'/{bucket.name}{path}', query, api_pre_auth_headers,
        payload, payload_hash)


class Read(asyncio.Future):
    @staticmethod
    def is_compatible(holds):
        return not holds[Write]


class Write(asyncio.Future):
    @staticmethod
    def is_compatible(holds):
        return not holds[Read] and not holds[Write]


class _PathLock():

    # https://people.eecs.berkeley.edu/~kubitron/courses/cs262a-F14/projects/reports/project6_report.pdf
    #
    # Inspired by ^ but a simpler version without the distinction between
    # "path" and "data" locks: I couldn't see the benefit of that

    def __init__(self):
        self._locks = weakref.WeakValueDictionary()

    @staticmethod
    def _sort_key(path_lock):
        return len(path_lock[0].parents), path_lock[0].as_posix()

    def _with_locks(self, paths, mode):
        return [
            (path, self._locks.setdefault(path, default=FifoLock()), mode)
            for path in paths
        ]

    @asynccontextmanager
    async def __call__(self, logger, paths):
        writable_paths = set(paths)
        writable_locks = self._with_locks(writable_paths, Write)

        ancestor_paths = _flatten(path.parents for path in paths)
        readable_paths = set(ancestor_paths) - writable_paths
        readable_locks = self._with_locks(readable_paths, Read)

        sorted_locks = sorted(readable_locks + writable_locks, key=self._sort_key)
        async with AsyncExitStack() as stack:
            for path, lock, mode in sorted_locks:
                with logged(logger, 'Locking %s on %s', [mode, path]):
                    await stack.enter_async_context(lock(mode))

            yield

            for path, _, _ in reversed(sorted_locks):
                logger.debug('Unlocking %s', path)


def _flatten(to_flatten):
    return [
        item
        for sub_list in to_flatten
        for item in sub_list
    ]
