FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG JUICEFS_VERSION=1.4.0

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        e2fsprogs \
        fuse3 \
        nbd-client \
        nbdkit \
        nbdkit-plugin-python \
        python3 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
      amd64) juicefs_sha="6dedd730487e7dac1b11c5801682a89692f2e6b97890baf7ac943407500b85ab" ;; \
      arm64) juicefs_sha="a23b3988623f59eb8cdc9dac723483203fd7b5ab2fa88e0d4219b68610b27c83" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && archive="juicefs-${JUICEFS_VERSION}-linux-${TARGETARCH}.tar.gz" \
    && curl -fsSL -o "/tmp/$archive" \
      "https://github.com/juicedata/juicefs/releases/download/v${JUICEFS_VERSION}/$archive" \
    && echo "$juicefs_sha  /tmp/$archive" | sha256sum -c - \
    && tar -xzf "/tmp/$archive" -C /usr/local/bin juicefs \
    && rm "/tmp/$archive" \
    && juicefs version

WORKDIR /opt/lazy-ext4-demo
COPY chunkstore.py lazy_chunk_plugin.py chunkctl.py demo.sh production_demo.sh ./
RUN chmod +x demo.sh production_demo.sh chunkctl.py

ENTRYPOINT ["/opt/lazy-ext4-demo/demo.sh"]
