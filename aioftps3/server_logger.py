import asyncio
import contextlib
import logging


class ContextAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return '[%s] %s' % (','.join(self.extra['context']), msg), kwargs


def get_logger_with_context(logger, context):
    return ContextAdapter(logger, {'context': [context]})


def get_child_logger(logger, child_context):
    existing_context = logger.extra['context']
    return ContextAdapter(logger.logger, {'context': existing_context + [child_context]})


@contextlib.contextmanager
def logged(logger, message, logger_args):
    try:
        logger.debug(message + '...', *logger_args)
        status = 'done'
        logger_func = logger.debug
        yield
    except asyncio.CancelledError:
        status = 'cancelled'
        logger_func = logger.debug
        raise
    except BaseException:
        status = 'failed'
        logger_func = logger.exception
        raise
    finally:
        logger_func(message + '... (%s)', *(logger_args + [status]))
