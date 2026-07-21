#!/usr/bin/env python3
"""Publish and inspect a raw disk as immutable Direct-S3 chunks."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import time

import boto3


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def key(prefix, suffix):
    return f"{prefix.strip('/')}/{suffix}"


def publish(args):
    source = os.path.abspath(args.source)
    size = os.path.getsize(source)
    if size % args.chunk_size:
        raise SystemExit("source size must be divisible by chunk size")
    client = boto3.client("s3", region_name=args.region)
    chunks = {}
    seen = set()
    futures = []
    uploaded_bytes = 0
    started = time.monotonic()
    descriptor = os.open(source, os.O_RDONLY)

    def upload(index, digest):
        data = os.pread(descriptor, args.chunk_size, index * args.chunk_size)
        client.put_object(
            Bucket=args.bucket,
            Key=key(args.prefix, f"objects/{digest}.chunk"),
            Body=data,
        )
        return len(data)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            for index in range(size // args.chunk_size):
                data = os.pread(descriptor, args.chunk_size, index * args.chunk_size)
                if not data.strip(b"\0"):
                    continue
                digest = hashlib.sha256(data).hexdigest()
                chunks[str(index)] = digest
                if digest not in seen:
                    seen.add(digest)
                    futures.append(pool.submit(upload, index, digest))
            for future in concurrent.futures.as_completed(futures):
                uploaded_bytes += future.result()
    finally:
        os.close(descriptor)

    volume = {"format": 1, "virtual_size": size, "chunk_size": args.chunk_size}
    manifest = {
        "format": 1,
        "generation": 1,
        "virtual_size": size,
        "chunk_size": args.chunk_size,
        "chunks": chunks,
    }
    data = json_bytes(manifest)
    digest = hashlib.sha256(data).hexdigest()
    name = f"generation-000001-{digest[:16]}.json"
    client.put_object(Bucket=args.bucket, Key=key(args.prefix, "volume.json"), Body=json_bytes(volume))
    client.put_object(Bucket=args.bucket, Key=key(args.prefix, f"manifests/{name}"), Body=data)
    client.put_object(
        Bucket=args.bucket,
        Key=key(args.prefix, "HEAD.json"),
        Body=json_bytes(
            {"format": 1, "generation": 1, "manifest": name, "manifest_sha256": digest}
        ),
    )
    print(
        json.dumps(
            {
                "bucket": args.bucket,
                "prefix": args.prefix.strip("/"),
                "virtual_size_bytes": size,
                "chunk_size_bytes": args.chunk_size,
                "mapped_chunks": len(chunks),
                "unique_objects": len(seen),
                "uploaded_bytes": uploaded_bytes,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            },
            sort_keys=True,
        )
    )


def clear_local(args):
    local = pathlib.Path(args.local).resolve()
    dirty = local / "dirty"
    if dirty.exists() and any(dirty.glob("*.dirty")):
        raise SystemExit(f"refusing to clear cache with dirty markers: {dirty}")
    cache = local / "cache"
    removed = 0
    if cache.exists():
        for path in cache.glob("*.chunk"):
            path.unlink()
            removed += 1
    stats = local / "stats.json"
    if stats.exists():
        stats.unlink()
    print(json.dumps({"cache_chunks_removed": removed, "local": str(local)}))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    pub = sub.add_parser("publish")
    pub.add_argument("--source", required=True)
    pub.add_argument("--bucket", required=True)
    pub.add_argument("--prefix", required=True)
    pub.add_argument("--region", default="us-east-1")
    pub.add_argument("--chunk-size", type=int, default=4 * 1024 * 1024)
    pub.add_argument("--workers", type=int, default=16)
    pub.set_defaults(function=publish)
    clear = sub.add_parser("clear-local")
    clear.add_argument("--local", required=True)
    clear.set_defaults(function=clear_local)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
