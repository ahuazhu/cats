"""Crash-consistent fixed-size chunk store used by the storage experiments.

The local directory models a host NVMe cache.  The remote directory is expected
to live on a durable POSIX filesystem such as JuiceFS.  Remote chunks and
generation manifests are immutable; HEAD is the only mutable publication point.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass


class InjectedCrash(RuntimeError):
    """Raised at an explicit commit boundary by the validation harness."""

    def __init__(self, point: str):
        super().__init__(f"injected crash at {point}")
        self.point = point


@dataclass(frozen=True)
class CommitResult:
    generation: int
    dirty: int
    uploaded: int
    reused: int
    unmapped: int
    recovered: bool = False


class ChunkStore:
    FORMAT = 2
    HEAD_FORMAT = 1
    CRASH_POINTS = {"after-objects", "after-manifest", "after-head"}

    def __init__(self, local_dir: str, remote_dir: str, size: int, chunk_size: int):
        self.local_dir = os.path.abspath(local_dir)
        self.remote_dir = os.path.abspath(remote_dir)
        self.virtual_size = int(size)
        self.chunk_size = int(chunk_size)

        if self.virtual_size <= 0 or self.chunk_size <= 0:
            raise ValueError("size and chunk_size must be positive")
        if self.virtual_size % 4096 or self.chunk_size % 4096:
            raise ValueError("size and chunk_size must be 4096-byte aligned")
        if self.virtual_size % self.chunk_size:
            raise ValueError("size must be a multiple of chunk_size")

        self.cache_dir = os.path.join(self.local_dir, "cache")
        self.dirty_dir = os.path.join(self.local_dir, "dirty")
        self.stats_path = os.path.join(self.local_dir, "stats.json")
        self.objects_dir = os.path.join(self.remote_dir, "objects")
        self.manifests_dir = os.path.join(self.remote_dir, "manifests")
        self.volume_path = os.path.join(self.remote_dir, "volume.json")
        self.head_path = os.path.join(self.remote_dir, "HEAD.json")

        for path in (
            self.local_dir,
            self.cache_dir,
            self.dirty_dir,
            self.remote_dir,
            self.objects_dir,
            self.manifests_dir,
        ):
            os.makedirs(path, exist_ok=True)

        self._validate_or_create_volume()
        self.manifest = self._load_head_manifest()

    def cache_path(self, index: int) -> str:
        return os.path.join(self.cache_dir, f"{index:016x}.chunk")

    def dirty_path(self, index: int) -> str:
        return os.path.join(self.dirty_dir, f"{index:016x}.dirty")

    def object_path(self, digest: str) -> str:
        return os.path.join(self.objects_dir, digest + ".chunk")

    def dirty_names(self) -> list[str]:
        return sorted(
            name for name in os.listdir(self.dirty_dir) if name.endswith(".dirty")
        )

    def fsync_local_dirty(self) -> None:
        for marker in self.dirty_names():
            index = int(marker[:-6], 16)
            path = self.cache_path(index)
            if os.path.exists(path):
                _fsync_file(path)
        _fsync_dir(self.cache_dir)
        _fsync_dir(self.dirty_dir)

    def commit(self, crash_at: str | None = None) -> CommitResult:
        if crash_at is not None and crash_at not in self.CRASH_POINTS:
            raise ValueError(f"unknown crash point: {crash_at}")

        dirty = self.dirty_names()
        if not dirty:
            return CommitResult(
                generation=self.manifest["generation"],
                dirty=0,
                uploaded=0,
                reused=0,
                unmapped=0,
            )

        self.fsync_local_dirty()
        next_chunks = dict(self.manifest["chunks"])
        uploaded = 0
        reused = 0
        unmapped = 0

        for marker in dirty:
            index_hex = marker[:-6]
            index = int(index_hex, 16)
            self._validate_index(index)
            cache_path = self.cache_path(index)
            key = str(index)

            if not os.path.exists(cache_path) or _file_is_all_zero(cache_path):
                if key in next_chunks:
                    del next_chunks[key]
                    unmapped += 1
                continue

            if os.path.getsize(cache_path) != self.chunk_size:
                raise RuntimeError(f"cache chunk has wrong size: {cache_path}")
            digest = _sha256_file(cache_path)
            object_path = self.object_path(digest)
            if os.path.exists(object_path):
                if os.path.getsize(object_path) != self.chunk_size:
                    raise RuntimeError(f"remote object has wrong size: {object_path}")
                reused += 1
            else:
                _copy_file_durable(cache_path, object_path)
                uploaded += 1
            next_chunks[key] = digest

        _fsync_dir(self.objects_dir)
        self._maybe_crash(crash_at, "after-objects")

        # A crash after publishing HEAD but before clearing dirty markers leaves
        # a fully committed generation.  A retry recognizes that state and only
        # performs the local cleanup instead of publishing a duplicate generation.
        if next_chunks == self.manifest["chunks"]:
            self._clear_dirty(dirty)
            return CommitResult(
                generation=self.manifest["generation"],
                dirty=len(dirty),
                uploaded=uploaded,
                reused=reused,
                unmapped=unmapped,
                recovered=True,
            )

        generation = self.manifest["generation"] + 1
        next_manifest = {
            "format": self.FORMAT,
            "generation": generation,
            "virtual_size": self.virtual_size,
            "chunk_size": self.chunk_size,
            "chunks": next_chunks,
        }
        manifest_data = _json_bytes(next_manifest)
        manifest_digest = hashlib.sha256(manifest_data).hexdigest()
        manifest_name = (
            f"generation-{generation:06d}-{manifest_digest[:16]}.json"
        )
        manifest_path = os.path.join(self.manifests_dir, manifest_name)
        _write_immutable(manifest_path, manifest_data)
        _fsync_dir(self.manifests_dir)
        self._maybe_crash(crash_at, "after-manifest")

        head = {
            "format": self.HEAD_FORMAT,
            "generation": generation,
            "manifest": manifest_name,
            "manifest_sha256": manifest_digest,
        }
        _write_json_atomic(self.head_path, head)
        _fsync_dir(self.remote_dir)
        self.manifest = next_manifest
        self._maybe_crash(crash_at, "after-head")

        self._clear_dirty(dirty)
        return CommitResult(
            generation=generation,
            dirty=len(dirty),
            uploaded=uploaded,
            reused=reused,
            unmapped=unmapped,
        )

    def clear_cache(self) -> int:
        dirty = self.dirty_names()
        if dirty:
            raise RuntimeError("refusing to clear cache while dirty chunks exist")
        removed = 0
        for name in os.listdir(self.cache_dir):
            path = os.path.join(self.cache_dir, name)
            if os.path.isfile(path):
                os.unlink(path)
                removed += 1
        if os.path.exists(self.stats_path):
            os.unlink(self.stats_path)
        _fsync_dir(self.cache_dir)
        return removed

    def report(self) -> dict:
        object_files = [
            os.path.join(self.objects_dir, name)
            for name in os.listdir(self.objects_dir)
            if name.endswith(".chunk")
        ]
        cache_files = [
            os.path.join(self.cache_dir, name)
            for name in os.listdir(self.cache_dir)
            if name.endswith(".chunk")
        ]
        manifest_files = [
            name for name in os.listdir(self.manifests_dir) if name.endswith(".json")
        ]
        referenced = set(self.manifest["chunks"].values())
        all_objects = {os.path.basename(path)[:-6] for path in object_files}
        result = {
            "generation": self.manifest["generation"],
            "virtual_size_bytes": self.virtual_size,
            "chunk_size_bytes": self.chunk_size,
            "virtual_chunk_count": self.virtual_size // self.chunk_size,
            "mapped_chunk_count": len(self.manifest["chunks"]),
            "object_count": len(object_files),
            "object_bytes": sum(os.path.getsize(path) for path in object_files),
            "head_referenced_object_count": len(referenced),
            "objects_not_referenced_by_head": len(all_objects - referenced),
            "manifest_count": len(manifest_files),
            "cache_chunk_count": len(cache_files),
            "cache_apparent_bytes": sum(os.path.getsize(path) for path in cache_files),
            "dirty_chunk_count": len(self.dirty_names()),
        }
        if os.path.exists(self.stats_path):
            with open(self.stats_path, "r", encoding="utf-8") as stream:
                result["backend_stats"] = json.load(stream)
        return result

    def verify(self) -> dict:
        checked = 0
        checked_bytes = 0
        for index_text, digest in self.manifest["chunks"].items():
            self._validate_index(int(index_text))
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise RuntimeError(f"invalid object digest: {digest}")
            path = self.object_path(digest)
            if not os.path.exists(path):
                raise RuntimeError(f"manifest references missing object: {digest}")
            if os.path.getsize(path) != self.chunk_size:
                raise RuntimeError(f"remote object has wrong size: {path}")
            actual = _sha256_file(path)
            if actual != digest:
                raise RuntimeError(f"remote object checksum mismatch: {digest}")
            checked += 1
            checked_bytes += self.chunk_size
        return {
            "generation": self.manifest["generation"],
            "verified_objects": checked,
            "verified_bytes": checked_bytes,
        }

    def _validate_or_create_volume(self) -> None:
        expected = {
            "format": self.FORMAT,
            "virtual_size": self.virtual_size,
            "chunk_size": self.chunk_size,
        }
        if os.path.exists(self.volume_path):
            with open(self.volume_path, "r", encoding="utf-8") as stream:
                actual = json.load(stream)
            if actual != expected:
                raise RuntimeError(
                    f"remote volume geometry differs: expected={expected} actual={actual}"
                )
        else:
            _write_json_atomic(self.volume_path, expected)

        if os.path.exists(self.head_path):
            return
        manifest = {
            "format": self.FORMAT,
            "generation": 0,
            "virtual_size": self.virtual_size,
            "chunk_size": self.chunk_size,
            "chunks": {},
        }
        data = _json_bytes(manifest)
        digest = hashlib.sha256(data).hexdigest()
        name = f"generation-000000-{digest[:16]}.json"
        _write_immutable(os.path.join(self.manifests_dir, name), data)
        _write_json_atomic(
            self.head_path,
            {
                "format": self.HEAD_FORMAT,
                "generation": 0,
                "manifest": name,
                "manifest_sha256": digest,
            },
        )
        _fsync_dir(self.remote_dir)

    def _load_head_manifest(self) -> dict:
        with open(self.head_path, "r", encoding="utf-8") as stream:
            head = json.load(stream)
        if head.get("format") != self.HEAD_FORMAT:
            raise RuntimeError("unsupported HEAD format")
        name = head.get("manifest")
        if not isinstance(name, str) or name != os.path.basename(name):
            raise RuntimeError("invalid manifest name in HEAD")
        path = os.path.join(self.manifests_dir, name)
        with open(path, "rb") as stream:
            data = stream.read()
        digest = hashlib.sha256(data).hexdigest()
        if digest != head.get("manifest_sha256"):
            raise RuntimeError("HEAD manifest checksum mismatch")
        manifest = json.loads(data)
        expected = (self.virtual_size, self.chunk_size)
        actual = (manifest.get("virtual_size"), manifest.get("chunk_size"))
        if manifest.get("format") != self.FORMAT or actual != expected:
            raise RuntimeError("manifest format or geometry mismatch")
        if manifest.get("generation") != head.get("generation"):
            raise RuntimeError("HEAD and manifest generation differ")
        if not isinstance(manifest.get("chunks"), dict):
            raise RuntimeError("manifest chunks must be an object")
        return manifest

    def _clear_dirty(self, dirty: list[str]) -> None:
        for marker in dirty:
            path = os.path.join(self.dirty_dir, marker)
            if os.path.exists(path):
                os.unlink(path)
        _fsync_dir(self.dirty_dir)
        if os.path.exists(self.stats_path):
            with open(self.stats_path, "r", encoding="utf-8") as stream:
                stats = json.load(stream)
            stats["dirty_chunks_current"] = len(self.dirty_names())
            _write_json_atomic(self.stats_path, stats)

    def _validate_index(self, index: int) -> None:
        if index < 0 or index >= self.virtual_size // self.chunk_size:
            raise RuntimeError(f"chunk index outside virtual disk: {index}")

    @staticmethod
    def _maybe_crash(requested: str | None, current: str) -> None:
        if requested == current:
            raise InjectedCrash(current)


def _json_bytes(value: dict) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _write_json_atomic(path: str, value: dict) -> None:
    _write_bytes_atomic(path, _json_bytes(value))


def _write_bytes_atomic(path: str, data: bytes) -> None:
    temporary = f"{path}.tmp.{os.getpid()}"
    with open(temporary, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    _fsync_dir(os.path.dirname(path))


def _write_immutable(path: str, data: bytes) -> None:
    if os.path.exists(path):
        with open(path, "rb") as stream:
            if stream.read() != data:
                raise RuntimeError(f"immutable file content differs: {path}")
        return
    _write_bytes_atomic(path, data)


def _copy_file_durable(source: str, destination: str) -> None:
    temporary = f"{destination}.tmp.{os.getpid()}"
    shutil.copyfile(source, temporary)
    _fsync_file(temporary)
    os.replace(temporary, destination)
    _fsync_dir(os.path.dirname(destination))


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            data = stream.read(1024 * 1024)
            if not data:
                return digest.hexdigest()
            digest.update(data)


def _file_is_all_zero(path: str) -> bool:
    with open(path, "rb") as stream:
        while True:
            data = stream.read(1024 * 1024)
            if not data:
                return True
            if data.strip(b"\0"):
                return False


def _fsync_file(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
