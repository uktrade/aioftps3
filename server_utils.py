import asyncio
import contextlib


def constant_time_compare(str_a, str_b):
    bytes_a = str_a.encode('utf-8')
    bytes_b = str_b.encode('utf-8')

    if len(bytes_a) != len(bytes_b):
        return False

    diffs = 0

    for char_a, char_b in zip(bytes_a, bytes_b):
        diffs |= char_a ^ char_b

    return diffs == 0


class Timeout(Exception):
    pass


@contextlib.asynccontextmanager
async def timeout(loop, max_time):

    cancelling_due_to_timeout = False
    current_task = asyncio.current_task()

    def cancel():
        nonlocal cancelling_due_to_timeout
        cancelling_due_to_timeout = True
        current_task.cancel()

    handle = loop.call_later(max_time, cancel)

    try:
        yield
    except asyncio.CancelledError:
        if not cancelling_due_to_timeout:
            raise
        else:
            raise Timeout()
    finally:
        handle.cancel()
