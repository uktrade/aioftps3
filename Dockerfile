FROM python:3.7.1-alpine3.8

ENV \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

RUN \
    apk add --no-cache \
        openssl=1.0.2p-r0 \
        tini=0.18.0-r0 && \
    apk add --no-cache --virtual .build-deps \
        build-base=0.5-r1 && \
    python3 -m ensurepip && \
    pip3 install pip==18.01 && \
    pip3 install \
        aioftp==0.12.0 \
        aiohttp==3.4.4 && \
    apk del .build-deps

COPY aioftps3.py /usr/local/lib/python3.7/site-packages/aioftps3.py
COPY server.py /server.py
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "server.py"]

RUN adduser -S ftps
USER ftps
