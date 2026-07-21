"""nbdkit Direct-S3 fixed-chunk block backend with a local NVMe cache.

This is a benchmark prototype: one writer, immutable content-addressed chunks,
immutable generation manifests, and HEAD as the publication point. It talks to
S3 with boto3 directly; no JuiceFS or S3 FUSE mount is involved.
"""

from __future__ import annotations

import hashlib
import builtins
import json
import os
import pathlib
import threading
import time

import boto3
import nbdkit
from botocore.exceptions import ClientError


API_VERSION = 2

_local = None
_bucket = None
_prefix = None
_region = "us-east-1"
_size = None
_chunk_size = None
_commit_on_flush = True
_client = None
_manifest = None
_cache_dir = None
_dirty_dir = None
_stats_path = None
_lock = threading.RLock()
_stats = {
    "read_requests": 0,
    "write_requests": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "hole_reads": 0,
    "object_get_requests": 0,
    "object_bytes_downloaded": 0,
    "s3_get_requests": 0,
    "s3_get_bytes": 0,
    "s3_get_ms": 0.0,
    "s3_put_requests": 0,
    "s3_put_bytes": 0,
    "s3_put_ms": 0.0,
    "bytes_written_to_cache": 0,
    "chunks_marked_dirty": 0,
    "dirty_chunks_current": 0,
    "flushes": 0,
    "remote_commits": 0,
    "remote_commit_dirty_chunks": 0,
}


def thread_model():
    return nbdkit.THREAD_MODEL_SERIALIZE_ALL_REQUESTS


def config(key, value):
    global _local, _bucket, _prefix, _region, _size, _chunk_size, _commit_on_flush
    if key == "local":
        _local = value
    elif key == "bucket":
        _bucket = value
    elif key == "prefix":
        _prefix = value.strip("/")
    elif key == "region":
        _region = value
    elif key == "size":
        _size = int(value)
    elif key == "chunk_size":
        _chunk_size = int(value)
    elif key == "commit_on_flush":
        _commit_on_flush = value.lower() in {"1", "true", "yes", "on"}
    else:
        raise RuntimeError(f"unknown parameter: {key}")


def config_complete():
    global _client, _manifest, _cache_dir, _dirty_dir, _stats_path
    if not all((_local, _bucket, _prefix, _size, _chunk_size)):
        raise RuntimeError("local, bucket, prefix, size, and chunk_size are required")
    if _size <= 0 or _chunk_size <= 0 or _size % _chunk_size:
        raise RuntimeError("invalid virtual disk geometry")
    _cache_dir = os.path.join(_local, "cache")
    _dirty_dir = os.path.join(_local, "dirty")
    _stats_path = os.path.join(_local, "stats.json")
    os.makedirs(_cache_dir, exist_ok=True)
    os.makedirs(_dirty_dir, exist_ok=True)
    _client = boto3.client("s3", region_name=_region)

    volume = _get_json("volume.json")
    expected = {"format": 1, "virtual_size": _size, "chunk_size": _chunk_size}
    if volume != expected:
        raise RuntimeError(f"remote volume geometry mismatch: {volume} != {expected}")
    head = _get_json("HEAD.json")
    data = _get_bytes(f"manifests/{head['manifest']}")
    if hashlib.sha256(data).hexdigest() != head["manifest_sha256"]:
        raise RuntimeError("HEAD manifest checksum mismatch")
    _manifest = json.loads(data)
    if _manifest["generation"] != head["generation"]:
        raise RuntimeError("HEAD generation mismatch")
    _save_stats()


def open(readonly):
    return {"readonly": readonly}


def get_size(handle):
    return _size


def can_write(handle):
    return not handle["readonly"]


def can_flush(handle):
    return True


def can_fua(handle):
    return nbdkit.FUA_EMULATE


def can_trim(handle):
    return True


def can_zero(handle):
    return True


def pread(handle, buf, offset, flags):
    with _lock:
        _stats["read_requests"] += 1
        target = memoryview(buf)
        written = 0
        while written < len(target):
            absolute = offset + written
            index = absolute // _chunk_size
            relative = absolute % _chunk_size
            length = min(len(target) - written, _chunk_size - relative)
            path = _cache_path(index)
            if os.path.exists(path):
                _stats["cache_hits"] += 1
                data = _pread_file(path, length, relative)
            else:
                digest = _manifest["chunks"].get(str(index))
                if digest:
                    _hydrate(index, digest)
                    data = _pread_file(path, length, relative)
                else:
                    _stats["hole_reads"] += 1
                    data = b"\0" * length
            target[written : written + length] = data
            written += length


def pwrite(handle, buf, offset, flags):
    if handle["readonly"]:
        raise PermissionError("read-only connection")
    with _lock:
        _stats["write_requests"] += 1
        source = memoryview(buf)
        consumed = 0
        while consumed < len(source):
            absolute = offset + consumed
            index = absolute // _chunk_size
            relative = absolute % _chunk_size
            length = min(len(source) - consumed, _chunk_size - relative)
            path = _ensure_writable(index)
            descriptor = os.open(path, os.O_RDWR)
            try:
                os.pwrite(descriptor, source[consumed : consumed + length], relative)
            finally:
                os.close(descriptor)
            _mark_dirty(index)
            _stats["bytes_written_to_cache"] += length
            consumed += length


def flush(handle, flags):
    with _lock:
        for index in _dirty_indices():
            path = _cache_path(index)
            if os.path.exists(path):
                descriptor = os.open(path, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        if _commit_on_flush:
            _commit()
        _stats["flushes"] += 1
        _save_stats()


def trim(handle, count, offset, flags):
    if handle["readonly"]:
        raise PermissionError("read-only connection")
    _zero(count, offset, allow_remove=True)


def zero(handle, count, offset, flags):
    if handle["readonly"]:
        raise PermissionError("read-only connection")
    _zero(count, offset, allow_remove=bool(flags & nbdkit.FLAG_MAY_TRIM))


def unload():
    with _lock:
        _save_stats()


def _key(suffix):
    return f"{_prefix}/{suffix}"


def _cache_path(index):
    return os.path.join(_cache_dir, f"{index:016x}.chunk")


def _dirty_path(index):
    return os.path.join(_dirty_dir, f"{index:016x}.dirty")


def _dirty_indices():
    return sorted(int(name[:-6], 16) for name in os.listdir(_dirty_dir) if name.endswith(".dirty"))


def _get_bytes(suffix, *, object_data=False):
    started = time.monotonic_ns()
    response = _client.get_object(Bucket=_bucket, Key=_key(suffix))
    data = response["Body"].read()
    _stats["s3_get_requests"] += 1
    _stats["s3_get_bytes"] += len(data)
    _stats["s3_get_ms"] += (time.monotonic_ns() - started) / 1_000_000
    if object_data:
        _stats["object_get_requests"] += 1
        _stats["object_bytes_downloaded"] += len(data)
    return data


def _get_json(suffix):
    return json.loads(_get_bytes(suffix))


def _put_bytes(suffix, data):
    started = time.monotonic_ns()
    _client.put_object(Bucket=_bucket, Key=_key(suffix), Body=data)
    _stats["s3_put_requests"] += 1
    _stats["s3_put_bytes"] += len(data)
    _stats["s3_put_ms"] += (time.monotonic_ns() - started) / 1_000_000


def _object_exists(digest):
    try:
        _client.head_object(Bucket=_bucket, Key=_key(f"objects/{digest}.chunk"))
        return True
    except ClientError as error:
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if status == 404:
            return False
        raise


def _hydrate(index, digest):
    data = _get_bytes(f"objects/{digest}.chunk", object_data=True)
    if len(data) != _chunk_size or hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError(f"invalid S3 object for chunk {index}: {digest}")
    destination = _cache_path(index)
    temporary = destination + ".tmp"
    with builtins.open(temporary, "wb") as stream:
        stream.write(data)
    os.replace(temporary, destination)
    _stats["cache_misses"] += 1
    _save_stats()


def _ensure_writable(index):
    path = _cache_path(index)
    if os.path.exists(path):
        return path
    digest = _manifest["chunks"].get(str(index))
    if digest:
        _hydrate(index, digest)
    else:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            os.ftruncate(descriptor, _chunk_size)
        finally:
            os.close(descriptor)
    return path


def _mark_dirty(index):
    path = _dirty_path(index)
    if not os.path.exists(path):
        pathlib.Path(path).touch()
        _stats["chunks_marked_dirty"] += 1
    _stats["dirty_chunks_current"] = len(_dirty_indices())


def _commit():
    global _manifest
    dirty = _dirty_indices()
    if not dirty:
        return
    chunks = dict(_manifest["chunks"])
    for index in dirty:
        path = _cache_path(index)
        if not os.path.exists(path) or _is_zero(path):
            chunks.pop(str(index), None)
            continue
        digest = _sha256(path)
        if not _object_exists(digest):
            with builtins.open(path, "rb") as stream:
                _put_bytes(f"objects/{digest}.chunk", stream.read())
        chunks[str(index)] = digest

    if chunks != _manifest["chunks"]:
        generation = _manifest["generation"] + 1
        manifest = {
            "format": 1,
            "generation": generation,
            "virtual_size": _size,
            "chunk_size": _chunk_size,
            "chunks": chunks,
        }
        data = _json_bytes(manifest)
        digest = hashlib.sha256(data).hexdigest()
        name = f"generation-{generation:06d}-{digest[:16]}.json"
        _put_bytes(f"manifests/{name}", data)
        _put_bytes(
            "HEAD.json",
            _json_bytes(
                {
                    "format": 1,
                    "generation": generation,
                    "manifest": name,
                    "manifest_sha256": digest,
                }
            ),
        )
        _manifest = manifest
        _stats["remote_commits"] += 1
        _stats["remote_commit_dirty_chunks"] += len(dirty)

    for index in dirty:
        try:
            os.unlink(_dirty_path(index))
        except FileNotFoundError:
            pass
    _stats["dirty_chunks_current"] = 0


def _zero(count, offset, allow_remove):
    with _lock:
        remaining = count
        while remaining:
            index = offset // _chunk_size
            relative = offset % _chunk_size
            length = min(remaining, _chunk_size - relative)
            if allow_remove and relative == 0 and length == _chunk_size:
                try:
                    os.unlink(_cache_path(index))
                except FileNotFoundError:
                    pass
            else:
                path = _ensure_writable(index)
                descriptor = os.open(path, os.O_RDWR)
                try:
                    os.pwrite(descriptor, b"\0" * length, relative)
                finally:
                    os.close(descriptor)
            _mark_dirty(index)
            offset += length
            remaining -= length


def _pread_file(path, count, offset):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        data = os.pread(descriptor, count, offset)
    finally:
        os.close(descriptor)
    return data + b"\0" * (count - len(data))


def _sha256(path):
    digest = hashlib.sha256()
    with builtins.open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_zero(path):
    with builtins.open(path, "rb") as stream:
        return all(not any(block) for block in iter(lambda: stream.read(1024 * 1024), b""))


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _save_stats():
    if not _stats_path:
        return
    temporary = _stats_path + ".tmp"
    with builtins.open(temporary, "w", encoding="utf-8") as stream:
        json.dump(_stats, stream, sort_keys=True)
    os.replace(temporary, _stats_path)
