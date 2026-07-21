"""nbdkit plugin exposing a sparse, crash-consistent chunk-backed disk.

This deliberately small backend models the Sprite/JuiceFS idea:

* immutable objects + generation manifests are the remote ground truth;
* cache/<index>.chunk is the local NVMe-like cache;
* dirty/<index>.dirty marks write-back chunks;
* reads hydrate one complete chunk on demand;
* writes are acknowledged after reaching the local cache;
* strict mode commits remote objects and HEAD for every NBD FLUSH.

The plugin is a teaching/validation tool, not production storage.
"""

import builtins
import json
import os
import shutil
import sys
import threading

import nbdkit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chunkstore import ChunkStore


API_VERSION = 2

_state_dir = None
_local_dir = None
_remote_dir = None
_virtual_size = None
_chunk_size = None
_commit_on_flush = False
_store = None
_cache_dir = None
_dirty_dir = None
_objects_dir = None
_manifest_path = None
_stats_path = None
_manifest = None
_lock = threading.RLock()
_stats = {
    "read_requests": 0,
    "write_requests": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "hole_reads": 0,
    "object_bytes_downloaded": 0,
    "bytes_written_to_cache": 0,
    "chunks_marked_dirty": 0,
    "flushes": 0,
    "remote_commits": 0,
    "remote_commit_dirty_chunks": 0,
}


def thread_model():
    # The demo favors simple, deterministic state transitions over throughput.
    return nbdkit.THREAD_MODEL_SERIALIZE_ALL_REQUESTS


def config(key, value):
    global _state_dir, _local_dir, _remote_dir
    global _virtual_size, _chunk_size, _commit_on_flush
    if key == "state":
        _state_dir = value
    elif key == "local":
        _local_dir = value
    elif key == "remote":
        _remote_dir = value
    elif key == "size":
        _virtual_size = int(value)
    elif key == "chunk_size":
        _chunk_size = int(value)
    elif key == "commit_on_flush":
        _commit_on_flush = value.lower() in ("1", "true", "yes", "on")
    else:
        raise RuntimeError("unknown parameter: " + key)


def config_complete():
    global _local_dir, _remote_dir, _store
    global _cache_dir, _dirty_dir, _objects_dir
    global _manifest_path, _stats_path, _manifest

    _local_dir = _local_dir or _state_dir
    _remote_dir = _remote_dir or _state_dir
    if not _local_dir or not _remote_dir or not _virtual_size or not _chunk_size:
        raise RuntimeError(
            "size, chunk_size, and either state or local+remote are required"
        )

    _store = ChunkStore(_local_dir, _remote_dir, _virtual_size, _chunk_size)
    _cache_dir = _store.cache_dir
    _dirty_dir = _store.dirty_dir
    _objects_dir = _store.objects_dir
    _manifest_path = _store.head_path
    _stats_path = _store.stats_path
    _manifest = _store.manifest

    _save_stats()


def open(readonly):
    return {"readonly": readonly}


def get_size(handle):
    return _virtual_size


def can_write(handle):
    return not handle["readonly"]


def can_flush(handle):
    return True


def can_fua(handle):
    # Let nbdkit translate every FUA write into pwrite followed by our FLUSH.
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
            cache_path = _cache_path(index)

            if os.path.exists(cache_path):
                _stats["cache_hits"] += 1
                data = _pread_file(cache_path, length, relative)
            else:
                digest = _manifest["chunks"].get(str(index))
                if digest:
                    _hydrate(index, digest)
                    data = _pread_file(cache_path, length, relative)
                else:
                    _stats["hole_reads"] += 1
                    data = b"\0" * length

            target[written:written + length] = data
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
            cache_path = _ensure_writable_chunk(index)
            fd = os.open(cache_path, os.O_RDWR)
            try:
                os.pwrite(fd, source[consumed:consumed + length], relative)
            finally:
                os.close(fd)
            _mark_dirty(index)
            consumed += length
            _stats["bytes_written_to_cache"] += length


def flush(handle, flags):
    global _manifest
    with _lock:
        _store.fsync_local_dirty()
        if _commit_on_flush:
            result = _store.commit()
            _manifest = _store.manifest
            if result.dirty:
                _stats["remote_commits"] += 1
                _stats["remote_commit_dirty_chunks"] += result.dirty
        _stats["flushes"] += 1
        _save_stats()


def trim(handle, count, offset, flags):
    if handle["readonly"]:
        raise PermissionError("read-only connection")
    _zero_or_trim(count, offset, allow_remove=True)


def zero(handle, count, offset, flags):
    if handle["readonly"]:
        raise PermissionError("read-only connection")
    _zero_or_trim(count, offset, allow_remove=bool(flags & nbdkit.FLAG_MAY_TRIM))


def unload():
    with _lock:
        _save_stats()


def _chunk_name(index):
    return f"{index:016x}.chunk"


def _cache_path(index):
    return _store.cache_path(index)


def _dirty_path(index):
    return _store.dirty_path(index)


def _object_path(digest):
    return _store.object_path(digest)


def _pread_file(path, count, offset):
    fd = os.open(path, os.O_RDONLY)
    try:
        data = os.pread(fd, count, offset)
    finally:
        os.close(fd)
    if len(data) < count:
        data += b"\0" * (count - len(data))
    return data


def _hydrate(index, digest):
    source = _object_path(digest)
    if not os.path.exists(source):
        raise RuntimeError(f"manifest references missing object {digest}")
    destination = _cache_path(index)
    temporary = destination + ".tmp"
    shutil.copyfile(source, temporary)
    os.replace(temporary, destination)
    _stats["cache_misses"] += 1
    _stats["object_bytes_downloaded"] += os.path.getsize(source)
    nbdkit.debug(f"CACHE MISS chunk={index} object={digest[:12]}")
    # A read-only cold mount might never issue FLUSH before disconnecting.
    # Persist on the relatively rare cache-miss path so the demo can retain
    # evidence of lazy object hydration without adding I/O to every read.
    _save_stats()


def _ensure_writable_chunk(index):
    path = _cache_path(index)
    if os.path.exists(path):
        return path

    digest = _manifest["chunks"].get(str(index))
    if digest:
        _hydrate(index, digest)
    else:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.ftruncate(fd, _chunk_size)
        finally:
            os.close(fd)
    return path


def _mark_dirty(index):
    marker = _dirty_path(index)
    if os.path.exists(marker):
        return
    fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    _stats["chunks_marked_dirty"] += 1


def _zero_or_trim(count, offset, allow_remove):
    with _lock:
        consumed = 0
        zero_page = b"\0" * min(_chunk_size, 1024 * 1024)
        while consumed < count:
            absolute = offset + consumed
            index = absolute // _chunk_size
            relative = absolute % _chunk_size
            length = min(count - consumed, _chunk_size - relative)

            if allow_remove and relative == 0 and length == _chunk_size:
                cache_path = _cache_path(index)
                existed = os.path.exists(cache_path) or str(index) in _manifest["chunks"]
                if os.path.exists(cache_path):
                    os.unlink(cache_path)
                if existed:
                    _mark_dirty(index)
            else:
                cache_path = _ensure_writable_chunk(index)
                fd = os.open(cache_path, os.O_RDWR)
                try:
                    remaining = length
                    position = relative
                    while remaining:
                        piece = zero_page[:min(remaining, len(zero_page))]
                        os.pwrite(fd, piece, position)
                        position += len(piece)
                        remaining -= len(piece)
                finally:
                    os.close(fd)
                _mark_dirty(index)
                _stats["bytes_written_to_cache"] += length
            consumed += length


def _save_stats():
    if not _stats_path:
        return
    data = dict(_stats)
    data["dirty_chunks_current"] = len([
        name for name in os.listdir(_dirty_dir) if name.endswith(".dirty")
    ])
    temporary = _stats_path + ".tmp"
    with builtins.open(temporary, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, _stats_path)


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
