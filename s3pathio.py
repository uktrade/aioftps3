import io

from aioftp.pathio import (
    AbstractPathIO,
    universal_exception,
)


class S3PathIO(AbstractPathIO):

    @universal_exception
    async def exists(self, path):
        raise NotImplementedError

    @universal_exception
    async def is_dir(self, path):
        raise NotImplementedError

    @universal_exception
    async def is_file(self, path):
        raise NotImplementedError

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
        raise NotImplementedError

    @universal_exception
    async def stat(self, path):
        raise NotImplementedError

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
