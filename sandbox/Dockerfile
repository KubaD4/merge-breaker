# Merge Breaker sandbox: runs untrusted repo code. It is never given real secrets.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace git ca-certificates coreutils \
    && rm -rf /var/lib/apt/lists/*
COPY detonate.mjs fuzz.mjs run-attacks.sh /opt/mb/
RUN chmod 755 /opt/mb/run-attacks.sh
USER node
WORKDIR /work
