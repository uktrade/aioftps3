FROM alpine:3.8

RUN \
    apk add --no-cache --virtual .build-deps \
        autoconf=2.69-r2 \
        automake=1.16.1-r0 \
        bash=4.4.19-r1 \
        build-base=0.5-r1 \
        curl-dev=7.61.1-r0 \
        fuse-dev=2.9.8-r0 \
        git=2.18.0-r0 \
        libxml2-dev=2.9.8-r0 && \
    apk add --no-cache \
        curl=7.61.1-r0 \
        fuse=2.9.8-r0 \
        libxml2=2.9.8-r0 \
        libstdc++=6.4.0-r9 && \
    git clone --branch v1.84 https://github.com/s3fs-fuse/s3fs-fuse.git && \
    ( \
        cd s3fs-fuse && \
        ./autogen.sh && \
        ./configure --prefix=/usr && \
        make && \
        make install \
    ) && \
    rm -r -f s3fs-fuse && \
    apk del .build-deps

RUN \
    adduser -S ftps

COPY entrypoint.sh entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# USER ftps
