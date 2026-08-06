#!/usr/bin/env python3
"""Copy one candidate output through no-follow dirfds into root staging."""

from __future__ import annotations

import os
import json
import pathlib
import re
import stat
import sys


TARGET_ROOT = pathlib.PurePosixPath("/srv/cats-build/target")
TARGET_BASE = re.compile(r"^[0-9a-f]{40}-[0-9a-f]{64}-[0-9a-f]{64}$")
JOB = re.compile(r"^job\.[A-Za-z0-9]+$")
MAX_BYTES = 5 * 1024 * 1024 * 1024


def fail(message: str) -> None:
    raise RuntimeError(message)


def main() -> int:
    if os.geteuid() != 0:
        fail("output staging must run as root")
    if len(sys.argv) != 3:
        fail("usage: stage-build-output <candidate-output> <new-root-staging-file>")
    source = pathlib.PurePosixPath(sys.argv[1])
    destination = pathlib.Path(sys.argv[2])
    try:
        relative = source.relative_to(TARGET_ROOT)
    except ValueError as error:
        raise RuntimeError("candidate output is outside the build target") from error
    parts = relative.parts
    if (
        len(parts) < 4
        or not TARGET_BASE.fullmatch(parts[0])
        or not JOB.fullmatch(parts[1])
        or parts[2] != "output"
        or any(part in ("", ".", "..") for part in parts)
    ):
        fail("candidate output path does not match the per-source per-job boundary")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(str(TARGET_ROOT), directory_flags)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        source_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            source_stat = os.fstat(source_fd)
            if (
                not stat.S_ISREG(source_stat.st_mode)
                or source_stat.st_uid != 0
                or source_stat.st_mode & 0o222
            ):
                fail("candidate output must be a frozen root-owned regular file")
            if source_stat.st_size > MAX_BYTES:
                fail("candidate output exceeds the 5 GiB single-object boundary")
            source_identity = (
                source_stat.st_dev,
                source_stat.st_ino,
                source_stat.st_size,
                source_stat.st_mtime_ns,
                source_stat.st_ctime_ns,
            )
            destination_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            try:
                while chunk := os.read(source_fd, 1024 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_fd, view)
                        view = view[written:]
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
            final_stat = os.fstat(source_fd)
            final_identity = (
                final_stat.st_dev,
                final_stat.st_ino,
                final_stat.st_size,
                final_stat.st_mtime_ns,
                final_stat.st_ctime_ns,
            )
            if final_identity != source_identity:
                destination.unlink(missing_ok=True)
                fail("candidate output changed while it was staged")
        finally:
            os.close(source_fd)
    finally:
        os.close(directory_fd)
    source_sha, manifest_sha256, bundle_sha256 = parts[0].split("-")
    print(
        json.dumps(
            {
                "schema_version": 1,
                "source_sha": source_sha,
                "manifest_sha256": manifest_sha256,
                "bundle_sha256": bundle_sha256,
                "job_id": parts[1],
                "output_relative_path": "/".join(parts[3:]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"stage failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
