import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='aioftps3',
    version='0.0.4',
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
