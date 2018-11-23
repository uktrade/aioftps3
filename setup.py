import re
import setuptools


def long_description():
    with open('README.md', 'r') as file:
        raw_description = file.read()

    regex = r'\[([^\]]+)\]\(([^\)]+)\)'
    relative_link_base = 'https://github.com/uktrade/aioftps3/blob/master/'

    def replace(match):
        text, url_maybe_absolute = match[1], match[2]
        is_absolute = \
            url_maybe_absolute.startswith('http://') or url_maybe_absolute.startswith('https://')
        url = \
            url_maybe_absolute if is_absolute else \
            relative_link_base + url_maybe_absolute

        return f'[{text}]({url})'

    return re.sub(regex, replace, raw_description)


setuptools.setup(
    name='aioftps3',
    version='0.0.6',
    author='Department for International Trade - WebOps',
    author_email='webops@digital.trade.gov.uk',
    description='FTP in front of AWS S3, powered by asyncio and aiohttp',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/uktrade/aioftps3',
    py_modules=[
        'aioftps3',
    ],
    install_requires=[
        'aiohttp',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Framework :: AsyncIO',
        'Topic :: Internet :: File Transfer Protocol (FTP)',
    ],
)
