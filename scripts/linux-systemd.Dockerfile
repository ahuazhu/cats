FROM rust:1.97.1-bookworm

ARG CATS_SOURCE_PROVENANCE_FINGERPRINT
LABEL io.cats.quality.source-fingerprint="${CATS_SOURCE_PROVENANCE_FINGERPRINT}"

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -qy --no-install-recommends \
        e2fsprogs \
        iproute2 \
        jq \
        systemd \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
