FROM docker.io/python:3.12-slim

ARG SNMPSIM_VERSION=1.2.2

RUN pip install --no-cache-dir \
    "snmpsim==${SNMPSIM_VERSION}" \
    "pysmi==2.0.0" \
    "cryptography==50.0.2"

COPY public.snmprec /usr/local/snmpsim/data/public.snmprec

USER nobody

# Each `--v3-user` option starts a new user. One user per security setting under test.
ENTRYPOINT ["snmpsim-command-responder", \
    "--v3-engine-id=auto", \
    "--data-dir=/usr/local/snmpsim/data", \
    "--agent-udpv4-endpoint=0.0.0.0:1161", \
    "--v3-user=noauth", \
    "--v3-user=authonly", "--v3-auth-key=authpass123", "--v3-auth-proto=SHA512", \
    "--v3-user=sha256aes", "--v3-auth-key=authpass123", "--v3-auth-proto=SHA256", \
        "--v3-priv-key=privpass123", "--v3-priv-proto=AES", \
    "--v3-user=aes256blmt", "--v3-auth-key=authpass123", "--v3-auth-proto=SHA", \
        "--v3-priv-key=privpass123", "--v3-priv-proto=AES256BLMT", \
    "--v3-user=aes256reeder", "--v3-auth-key=authpass123", "--v3-auth-proto=SHA", \
        "--v3-priv-key=privpass123", "--v3-priv-proto=AES256"]
