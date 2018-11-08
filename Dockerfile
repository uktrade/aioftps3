FROM python:3.7.1-alpine3.8

ENV \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

RUN \
    apk add --no-cache \
        build-base==0.5-r1 && \
    apk add --no-cache \
        openssl=1.0.2p-r0 \
        tini=0.18.0-r0 && \
    python3 -m ensurepip && \
    pip3 install pip==18.01 && \
    pip3 install \
        aiodns==1.1.1 \
        aiohttp==3.4.4 && \
    apk del build-base

COPY entrypoint.sh /entrypoint.sh
COPY server.py /server.py
COPY server_logger.py /server_logger.py
COPY server_s3.py /server_s3.py
COPY server_socket.py /server_socket.py
COPY server_utils.py /server_utils.py

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "server.py"]

RUN adduser -S ftps
USER ftps
