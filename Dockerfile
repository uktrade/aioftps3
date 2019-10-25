FROM python:3.7.1-alpine3.8

ENV \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8

COPY requirements.txt /

RUN \
    apk add --no-cache \
        build-base==0.5-r1 && \
    apk add --no-cache \
        openssl=1.0.2t-r0 \
        tini=0.18.0-r0 && \
    python3 -m ensurepip && \
    pip3 install pip==18.01 && \
    pip3 install -r requirements.txt && \
    apk del build-base

COPY ["README.md", "setup.py", "/"]
COPY aioftps3 aioftps3
RUN pip install --no-dependencies -e .

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "-m", "aioftps3.server_main"]

RUN adduser -S ftps
USER ftps
