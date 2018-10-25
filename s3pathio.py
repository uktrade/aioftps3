from collections import (
    namedtuple,
)
import io

from aioftp.pathio import (
    AbstractPathIO,
    universal_exception,
)


Stat = namedtuple(
    'Stat',
    ['st_size', 'st_mtime', 'st_ctime', 'st_nlink', 'st_mode'],
)

Node = namedtuple(
    'Node',
    ['name', 'type', 'stat'],
)


class S3PathIO(AbstractPathIO):

    @universal_exception
    async def exists(self, path):
        return True

    @universal_exception
    async def is_dir(self, node):
        return node.type == 'dir'

    @universal_exception
    async def is_file(self, node):
        return node.type == 'file'

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
        return _list(path)

    @universal_exception
    async def stat(self, node):
        return node.stat

    @universal_exception
    async def _open(self, path, mode):
        raise NotImplementedError

    @universal_exception
    async def seek(self, file, offset, whence=io.SEEK_SET):
        raise NotImplementedError

    @universal_exception
    async def write(self, file, data):
        raise NotImplementedError

    @universal_exception
    async def read(self, file, block_size):
        raise NotImplementedError

    @universal_exception
    async def close(self, file):
        raise NotImplementedError

    @universal_exception
    async def rename(self, source, destination):
        raise NotImplementedError


async def _list(_):
    for name in ['dummy_1', 'dummy_2']:
        yield Node(
            name=name,
            type='file',
            stat=Stat(
                st_size=1,
                st_mtime=0,
                st_ctime=0,
                st_nlink=1,
                st_mode=0o100666,
            ),
        )
