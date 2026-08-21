#!/usr/bin/env python3
"""Black-box fixture for the E13 public-trust supply chain."""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any


SOURCE = "3" * 40
DEPLOYMENT = "production-fixture"
RELEASE = "sha256:" + "4" * 64


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def run(
    command: list[str],
    *,
    success: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, check=False, capture_output=True, env=env)
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected exit {result.returncode}: {' '.join(command)}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return result


def wait_for_path(path: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 5
    while not path.exists() and time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"publisher exited before {path} appeared: "
                f"returncode={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
        time.sleep(0.01)
    assert path.exists(), f"publisher did not create {path}"


def start_barrier_publisher(
    command: list[str], output: Path, fifo: Path
) -> tuple[subprocess.Popen[bytes], int]:
    os.mkfifo(fifo, 0o600)
    barrier_read, barrier_write = os.pipe()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **os.environ,
                "CATS_E13_TRUST_FIXTURE_BARRIER_OUTPUT": output.name,
                # The current implementation consumes only the inherited fd.
                # The FIFO keeps this race executable against pre-fix 78acea0f
                # to prove the old implementation red before accepting green.
                "CATS_E13_TRUST_FIXTURE_BARRIER_FD": str(barrier_read),
                "CATS_E13_TRUST_FIXTURE_BARRIER_FIFO": str(fifo),
            },
            pass_fds=(barrier_read,),
        )
    finally:
        os.close(barrier_read)
    return process, barrier_write


def release_barrier(
    process: subprocess.Popen[bytes], barrier_write: int, fifo: Path
) -> None:
    try:
        try:
            os.write(barrier_write, b"x")
        except BrokenPipeError:
            # Seeing the temporary file only proves that publication entered
            # its descriptor-pinned sequence. A parent or lock ABA may be
            # detected by one of the subsequent pre-barrier revalidations, in
            # which case the safe publisher exits before reading this pipe.
            # Accept only that completed fail-closed outcome; a live process
            # that dropped its barrier reader is a fixture contract failure.
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise AssertionError(
                    "publisher dropped the barrier reader without exiting"
                ) from error
            return
    finally:
        os.close(barrier_write)

    # A pre-fix tool blocks opening the named FIFO. A fixed tool has no FIFO
    # reader, so ENXIO is expected until that process consumes the fd and exits.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            fifo_descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as error:
            if error.errno != errno.ENXIO:
                raise
            if process.poll() is not None:
                return
            time.sleep(0.01)
            continue
        try:
            os.write(fifo_descriptor, b"x")
        finally:
            os.close(fifo_descriptor)
        return


def exercise_parent_swap(tool: Path, openssl: Path, root: Path) -> None:
    """One lexical path must never create two independently locked authorities."""

    base = root / "parent-swap"
    base.mkdir(mode=0o700)
    live = base / "authority"
    live.mkdir(mode=0o700)
    command = generation_command(
        tool, openssl, live, credential_id="fixture-parent-swap"
    )
    private_key = live / "offline-operator-key.pem"
    temporary = private_key.with_name(f".{private_key.name}.cats-publish-v1")
    fifo = base / "publish-barrier.fifo"
    first, barrier_write = start_barrier_publisher(command, private_key, fifo)
    try:
        wait_for_path(temporary, first)
        assert temporary.stat().st_size == 0
        lock_name = f".{private_key.name}.cats-publish-v1.lock"
        first_lock_metadata = (live / lock_name).stat(follow_symlinks=False)

        detached = base / "authority-detached"
        live.rename(detached)
        live.mkdir(mode=0o700)
        second = run(command)
        second_lock_metadata = (live / lock_name).stat(follow_symlinks=False)
        first_lock = (first_lock_metadata.st_dev, first_lock_metadata.st_ino)
        second_lock = (second_lock_metadata.st_dev, second_lock_metadata.st_ino)
        assert first_lock != second_lock

        replacement = base / "authority-replacement"
        live.rename(replacement)
        live.mkdir(mode=0o700)
        # Move A's still-open temp inode back to its original lexical name.
        # Pre-fix absolute link/unlink calls now publish it into this third
        # directory, while the fixed implementation uses its pinned dirfd and
        # rejects that the original parent is no longer canonically bound.
        (detached / temporary.name).rename(temporary)
        release_descriptor = barrier_write
        barrier_write = -1
        release_barrier(first, release_descriptor, fifo)
        first_stdout, first_stderr = first.communicate(timeout=10)
        original_final = private_key.exists()
        replacement_final = (replacement / private_key.name).exists()
        assert second.returncode == 0
        assert first.returncode != 0 and not original_final and replacement_final, (
            "parent swap did not fail closed: "
            f"returncodes={(first.returncode, second.returncode)}, "
            f"lock_identities={(first_lock, second_lock)}, "
            f"private_outputs={(original_final, replacement_final)}, "
            f"first_stdout={first_stdout!r}, first_stderr={first_stderr!r}"
        )
        assert temporary.stat().st_size == 0
        assert b"PRIVATE KEY" not in temporary.read_bytes()
    finally:
        if barrier_write >= 0:
            os.close(barrier_write)
        if first.poll() is None:
            first.kill()
            first.communicate()


def exercise_lock_aba(tool: Path, openssl: Path, root: Path) -> None:
    """Unlinking the held lock pathname must make the old writer fail closed."""

    aba_root = root / "lock-aba"
    aba_root.mkdir(mode=0o700)
    command = generation_command(
        tool, openssl, aba_root, credential_id="fixture-lock-aba"
    )
    private_key = aba_root / "offline-operator-key.pem"
    temporary = private_key.with_name(f".{private_key.name}.cats-publish-v1")
    lock = private_key.with_name(f".{private_key.name}.cats-publish-v1.lock")
    fifo = root / "lock-aba-barrier.fifo"
    first, barrier_write = start_barrier_publisher(command, private_key, fifo)
    try:
        wait_for_path(temporary, first)
        original_lock = lock.stat(follow_symlinks=False)
        lock.unlink()
        replacement_descriptor = os.open(
            lock,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        os.close(replacement_descriptor)
        replacement_lock = lock.stat(follow_symlinks=False)
        assert (original_lock.st_dev, original_lock.st_ino) != (
            replacement_lock.st_dev,
            replacement_lock.st_ino,
        )
        second = run(command)
        final_before = private_key.read_bytes()
        release_descriptor = barrier_write
        barrier_write = -1
        release_barrier(first, release_descriptor, fifo)
        _, first_stderr = first.communicate(timeout=10)
        assert second.returncode == 0
        assert first.returncode != 0, first_stderr
        assert private_key.read_bytes() == final_before
        assert private_key.stat().st_nlink == 1
    finally:
        if barrier_write >= 0:
            os.close(barrier_write)
        if first.poll() is None:
            first.kill()
            first.communicate()


def exercise_ancestry_rejections(tool: Path, openssl: Path, root: Path) -> None:
    """Symlinked or writable output ancestry is never publication authority."""

    real_parent = root / "real-output-parent"
    real_parent.mkdir(mode=0o700)
    symlink_parent = root / "symlink-output-parent"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    symlink_command = generation_command(
        tool, openssl, symlink_parent, credential_id="fixture-symlink-parent"
    )
    run(symlink_command, success=False)
    assert not (real_parent / "offline-operator-key.pem").exists()

    writable_ancestor = root / "writable-ancestor"
    writable_ancestor.mkdir(mode=0o700)
    writable_ancestor.chmod(0o777)
    protected_parent = writable_ancestor / "protected-output-parent"
    protected_parent.mkdir(mode=0o700)
    writable_command = generation_command(
        tool, openssl, protected_parent, credential_id="fixture-writable-ancestor"
    )
    run(writable_command, success=False)
    assert not (protected_parent / "offline-operator-key.pem").exists()


def load_authority_module(tool: Path) -> Any:
    module_name = "cats_production_cutover_operator_trust_fixture"
    specification = importlib.util.spec_from_file_location(module_name, tool)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    specification.loader.exec_module(module)
    return module


def expect_trust_error(module: Any, operation: Any) -> None:
    try:
        operation()
    except module.TrustError:
        return
    raise AssertionError("final-open layout operation did not fail closed")


def exercise_final_open_layout(tool: Path, root: Path) -> None:
    """The operator installer owns one exact, secret-free final-open layout."""

    module = load_authority_module(tool)
    assert str(module.FINAL_OPEN_STATE_ROOT) == "/var/lib/cats/production-final-open"
    assert str(module.FINAL_OPEN_ADMISSION_STATE) == (
        "/var/lib/cats/production-final-open/admission-state"
    )
    assert str(module.FINAL_OPEN_RECEIPTS) == (
        "/var/lib/cats/production-final-open/receipts"
    )

    state_root = root / "final-open-layout"
    layout = module.provision_final_open_state_layout(
        state_root, require_root=False
    )
    replay = module.provision_final_open_state_layout(
        state_root, require_root=False
    )
    assert replay == layout
    assert set(layout) == {
        "admission_state",
        "direct_children",
        "receipts",
        "root",
    }
    assert layout["direct_children"] == ["admission-state", "receipts"]
    expected_paths = {
        "root": state_root,
        "admission_state": state_root / "admission-state",
        "receipts": state_root / "receipts",
    }
    for label, expected_path in expected_paths.items():
        entry = layout[label]
        assert set(entry) == {"gid", "mode", "path", "type", "uid"}
        assert entry == {
            "gid": os.getegid(),
            "mode": "0700",
            "path": str(expected_path),
            "type": "directory",
            "uid": os.geteuid(),
        }
        metadata = expected_path.stat(follow_symlinks=False)
        assert metadata.st_mode & 0o777 == 0o700
    encoded = canonical(layout)
    assert b"inode" not in encoded and b"device" not in encoded
    assert all(path.is_dir() for path in state_root.iterdir())
    assert not any(path.is_file() for path in state_root.rglob("*"))

    foreign_root = root / "final-open-foreign"
    foreign_root.mkdir(mode=0o700)
    foreign = foreign_root / "foreign"
    foreign.write_bytes(b"foreign-state\n")
    foreign.chmod(0o600)
    expect_trust_error(
        module,
        lambda: module.provision_final_open_state_layout(
            foreign_root, require_root=False
        ),
    )
    assert foreign.read_bytes() == b"foreign-state\n"

    symlink_target = root / "final-open-symlink-target"
    symlink_target.mkdir(mode=0o700)
    symlink_root = root / "final-open-symlink"
    symlink_root.symlink_to(symlink_target, target_is_directory=True)
    expect_trust_error(
        module,
        lambda: module.provision_final_open_state_layout(
            symlink_root, require_root=False
        ),
    )
    assert not list(symlink_target.iterdir())

    child_symlink_root = root / "final-open-child-symlink"
    child_symlink_root.mkdir(mode=0o700)
    child_target = root / "final-open-child-target"
    child_target.mkdir(mode=0o700)
    (child_symlink_root / "admission-state").symlink_to(
        child_target, target_is_directory=True
    )
    expect_trust_error(
        module,
        lambda: module.provision_final_open_state_layout(
            child_symlink_root, require_root=False
        ),
    )
    assert not list(child_target.iterdir())

    wrong_mode_root = root / "final-open-wrong-mode"
    wrong_mode_root.mkdir(mode=0o700)
    wrong_mode_root.chmod(0o755)
    expect_trust_error(
        module,
        lambda: module.provision_final_open_state_layout(
            wrong_mode_root, require_root=False
        ),
    )
    assert not list(wrong_mode_root.iterdir())

    writable_ancestor = root / "final-open-writable-ancestor"
    writable_ancestor.mkdir(mode=0o700)
    writable_ancestor.chmod(0o777)
    rejected_root = writable_ancestor / "production-final-open"
    expect_trust_error(
        module,
        lambda: module.provision_final_open_state_layout(
            rejected_root, require_root=False
        ),
    )
    assert not rejected_root.exists()

    swap_parent = root / "final-open-swap-parent"
    swap_parent.mkdir(mode=0o700)
    swap_root = swap_parent / "production-final-open"
    detached_parent = root / "final-open-swap-parent-detached"
    original_mkdir = module.os.mkdir
    swapped = False

    def swap_before_mkdir(
        path: Any,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if path == swap_root.name and dir_fd is not None and not swapped:
            swapped = True
            swap_parent.rename(detached_parent)
            original_mkdir(swap_parent, 0o700)
        original_mkdir(path, mode, dir_fd=dir_fd)

    module.os.mkdir = swap_before_mkdir
    try:
        expect_trust_error(
            module,
            lambda: module.provision_final_open_state_layout(
                swap_root, require_root=False
            ),
        )
    finally:
        module.os.mkdir = original_mkdir
    assert swapped
    assert not swap_root.exists()
    detached_root = detached_parent / swap_root.name
    assert detached_root.is_dir()
    assert not list(detached_root.iterdir())


def generation_command(
    tool: Path,
    openssl: Path,
    root: Path,
    *,
    credential_id: str,
) -> list[str]:
    return [
        sys.executable,
        "-B",
        str(tool),
        "generate",
        "--deployment-id",
        DEPLOYMENT,
        "--release-id",
        RELEASE,
        "--source-commit",
        SOURCE,
        "--credential-id",
        credential_id,
        "--aws-partition",
        "aws",
        "--account-id",
        "123456789012",
        "--role-arn",
        "arn:aws:iam::123456789012:role/cats-production-cutover",
        "--private-key-out",
        str(root / "offline-operator-key.pem"),
        "--trust-out",
        str(root / "production-cutover-operator-trust.v1.json"),
        "--generation-receipt-out",
        str(root / "production-cutover-operator-trust-generation.receipt.json"),
        "--openssl",
        str(openssl),
    ]


def assert_interrupted_link_pair(path: Path) -> None:
    temporary = path.with_name(f".{path.name}.cats-publish-v1")
    final_metadata = path.stat(follow_symlinks=False)
    temporary_metadata = temporary.stat(follow_symlinks=False)
    assert final_metadata.st_nlink == 2
    assert temporary_metadata.st_nlink == 2
    assert (final_metadata.st_dev, final_metadata.st_ino) == (
        temporary_metadata.st_dev,
        temporary_metadata.st_ino,
    )


def common_public(tool: Path, trust: Path, generation: Path) -> list[str]:
    return [
        sys.executable,
        "-B",
        str(tool),
        "verify-public",
        "--trust-file",
        str(trust),
        "--generation-receipt",
        str(generation),
        "--expected-source-commit",
        SOURCE,
        "--expected-deployment-id",
        DEPLOYMENT,
        "--expected-release-id",
        RELEASE,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, type=Path)
    parser.add_argument("--openssl", required=True, type=Path)
    parser.add_argument(
        "--authority-race-only",
        action="store_true",
        help="run only the real parent-swap regression against a selected tool",
    )
    args = parser.parse_args()
    tool = args.tool.resolve(strict=True)
    openssl = args.openssl.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix="cats-e13-trust-fixture-") as temporary:
        # macOS exposes its real temporary root through a /var symlink. Resolve
        # once in the harness; the authority tool itself must reject symlinked
        # output ancestry instead of silently canonicalizing caller input.
        root = Path(temporary).resolve(strict=True)
        root.chmod(0o700)
        exercise_parent_swap(tool, openssl, root)
        if args.authority_race_only:
            print("production cutover operator parent-swap regression passed")
            return 0
        exercise_ancestry_rejections(tool, openssl, root)
        exercise_final_open_layout(tool, root)
        private_key = root / "offline-operator-key.pem"
        trust = root / "production-cutover-operator-trust.v1.json"
        generation = root / "production-cutover-operator-trust-generation.receipt.json"
        generate = generation_command(
            tool, openssl, root, credential_id="fixture-operator"
        )
        killed = run(
            generate,
            success=False,
            env={
                **os.environ,
                "CATS_E13_TRUST_FIXTURE_KILL_AFTER_LINK": private_key.name,
            },
        )
        assert killed.returncode < 0
        assert_interrupted_link_pair(private_key)
        generated = run(generate)
        assert not private_key.with_name(
            f".{private_key.name}.cats-publish-v1"
        ).exists()
        assert private_key.stat().st_nlink == 1
        assert private_key.stat().st_mode & 0o777 == 0o600
        assert trust.stat().st_mode & 0o777 == 0o644
        assert generation.stat().st_mode & 0o777 == 0o600
        generated_result = json.loads(generated.stdout)
        assert "private_key" not in generated.stdout.decode().lower()
        assert str(private_key).encode() not in generated.stdout
        assert generated_result["trust_sha256"] == digest(trust.read_bytes())
        trust_value = json.loads(trust.read_bytes())
        assert canonical(trust_value) == trust.read_bytes()
        assert trust_value["credentials"][0]["scope"]["role_arn"].endswith(
            "/cats-production-cutover"
        )
        generation_raw = generation.read_bytes()
        assert canonical(json.loads(generation_raw)) == generation_raw
        assert b"PRIVATE KEY" not in generation_raw
        assert b"private" not in generation_raw.lower()

        # A kill after deterministic temp creation but before the first byte
        # leaves a zero-size inode. The persistent lock proves the writer died,
        # so re-entry removes only that incomplete state and finishes normally.
        zero_root = root / "zero-temp-crash"
        zero_root.mkdir(mode=0o700)
        zero_command = generation_command(
            tool, openssl, zero_root, credential_id="fixture-zero-temp"
        )
        zero_private = zero_root / private_key.name
        killed = run(
            zero_command,
            success=False,
            env={
                **os.environ,
                "CATS_E13_TRUST_FIXTURE_KILL_AFTER_TEMP_CREATE": zero_private.name,
            },
        )
        assert killed.returncode < 0
        zero_temporary = zero_private.with_name(
            f".{zero_private.name}.cats-publish-v1"
        )
        assert not zero_private.exists()
        assert zero_temporary.stat().st_size == 0
        run(zero_command)
        assert zero_private.stat().st_nlink == 1
        assert not zero_temporary.exists()

        # Hold process A after creating its zero-size temp. Process B must wait
        # on the same persistent flock, then replay A's completed key instead
        # of publishing partial bytes or rotating the key.
        race_root = root / "concurrent-publish"
        race_root.mkdir(mode=0o700)
        race_command = generation_command(
            tool, openssl, race_root, credential_id="fixture-concurrent"
        )
        race_private = race_root / private_key.name
        barrier = root / "concurrent-publish-barrier.fifo"
        first, barrier_write = start_barrier_publisher(
            race_command, race_private, barrier
        )
        second: subprocess.Popen[bytes] | None = None
        try:
            race_temporary = race_private.with_name(
                f".{race_private.name}.cats-publish-v1"
            )
            wait_for_path(race_temporary, first)
            assert race_temporary.stat().st_size == 0
            second = subprocess.Popen(
                race_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.1)
            assert second.poll() is None
            release_descriptor = barrier_write
            barrier_write = -1
            release_barrier(first, release_descriptor, barrier)
            first_stdout, first_stderr = first.communicate(timeout=10)
            second_stdout, second_stderr = second.communicate(timeout=10)
            assert first.returncode == 0, first_stderr
            assert second.returncode == 0, second_stderr
            assert json.loads(first_stdout) == json.loads(second_stdout)
            assert race_private.stat().st_nlink == 1
            assert not race_temporary.exists()
        finally:
            if barrier_write >= 0:
                os.close(barrier_write)
            for process in (first, second):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate()
        exercise_lock_aba(tool, openssl, root)
        # The current manual-release manifest closes exactly {control_plane,
        # credential_refresher, gateway, worker}; public trust is not a member.
        release_manifest = root / "release-manifest.v1.json"
        fixture_digest = "sha256:" + "5" * 64
        release_manifest_value = {
            "artifacts": {
                "control_plane": {
                    "guest_manifest_sha256": fixture_digest,
                    "guest_profile_sha256": fixture_digest,
                    "image_config_digest": fixture_digest,
                    "image_digest": fixture_digest,
                    "image_reference": "registry.example/cats/control:fixture",
                    "registry_verified": True,
                },
                "credential_refresher": {
                    "image_config_digest": fixture_digest,
                    "image_digest": fixture_digest,
                    "image_reference": "registry.example/cats/credential-refresher:fixture",
                    "refresh_program_sha256": fixture_digest,
                    "registry_verified": True,
                    "swap_dsn_program_sha256": fixture_digest,
                },
                "gateway": {
                    "binary_sha256": fixture_digest,
                    "binary_size_bytes": 1,
                    "image_config_digest": fixture_digest,
                    "image_digest": fixture_digest,
                    "image_reference": "registry.example/cats/gateway:fixture",
                    "registry_verified": True,
                },
                "worker": {
                    "bundle_name": "cats-worker.tar.zst",
                    "bundle_sha256": fixture_digest,
                    "bundle_size_bytes": 1,
                    "guest_initramfs_sha256": None,
                    "guest_kernel_sha256": fixture_digest,
                    "guest_manifest_sha256": fixture_digest,
                    "guest_profile_sha256": fixture_digest,
                    "members": {
                        "cats-noded": {"sha256": fixture_digest, "size_bytes": 1}
                    },
                },
            },
            "build_inputs": {
                "files": {},
                "fingerprint": fixture_digest,
                "guest_target": "x86_64-unknown-linux-musl",
                "platform": "linux/amd64",
            },
            "guest_runtime": {
                "initramfs": None,
                "kernel": {
                    "path": "guest/vmlinuz",
                    "sha256": fixture_digest,
                    "size_bytes": 1,
                },
                "manifest_sha256": fixture_digest,
                "profile_sha256": fixture_digest,
                "release_id": fixture_digest,
            },
            "source": {
                "commit": SOURCE,
                "fingerprint": fixture_digest,
                "tree": "6" * 40,
            },
            "version": 1,
        }
        release_manifest.write_bytes(canonical(release_manifest_value))
        release_manifest.chmod(0o644)
        release_manifest_digest = digest(release_manifest.read_bytes())

        verification = root / "production-cutover-operator-trust-verification.receipt.json"
        verify_command = [
            sys.executable,
            "-B",
            str(tool),
            "verify",
            "--trust-file",
            str(trust),
            "--generation-receipt",
            str(generation),
            "--private-key-file",
            str(private_key),
            "--verification-receipt-out",
            str(verification),
            "--expected-source-commit",
            SOURCE,
            "--expected-deployment-id",
            DEPLOYMENT,
            "--expected-release-id",
            RELEASE,
            "--openssl",
            str(openssl),
        ]
        killed = run(
            verify_command,
            success=False,
            env={
                **os.environ,
                "CATS_E13_TRUST_FIXTURE_KILL_AFTER_LINK": verification.name,
            },
        )
        assert killed.returncode < 0
        assert_interrupted_link_pair(verification)
        verified = run(verify_command)
        assert verification.stat().st_nlink == 1
        assert verification.stat().st_mode & 0o777 == 0o600
        assert b"private" not in verification.read_bytes().lower()
        assert b"private_key" not in verified.stdout.lower()
        assert str(private_key).encode() not in verified.stdout

        package = root / "package"
        package.mkdir(mode=0o700)
        manifest = package / "secret.json"
        package_receipt = package / "receipt.json"
        run(
            [
                sys.executable,
                "-B",
                str(tool),
                "package-kubernetes",
                "--trust-file",
                str(trust),
                "--generation-receipt",
                str(generation),
                "--secret-name",
                "cats-production-cutover-operator-trust-r1",
                "--namespace",
                "cats",
                "--manifest-out",
                str(manifest),
                "--receipt-out",
                str(package_receipt),
                "--expected-source-commit",
                SOURCE,
                "--expected-deployment-id",
                DEPLOYMENT,
                "--expected-release-id",
                RELEASE,
                "--release-manifest",
                str(release_manifest),
                "--release-manifest-sha256",
                release_manifest_digest,
            ]
        )
        manifest_raw = manifest.read_bytes()
        manifest_value = json.loads(manifest_raw)
        assert canonical(manifest_value) == manifest_raw
        assert manifest_value["immutable"] is True
        assert list(manifest_value["data"]) == [
            "production-cutover-operator-trust.v1.json"
        ]
        assert base64.b64decode(next(iter(manifest_value["data"].values()))) == trust.read_bytes()
        assert (
            manifest_value["metadata"]["annotations"][
                "cats.run/production-cutover-operator-trust-sha256"
            ]
            == digest(trust.read_bytes())
        )
        assert b"PRIVATE KEY" not in manifest_raw
        assert b"private" not in package_receipt.read_bytes().lower()
        assert (
            json.loads(package_receipt.read_bytes())["release_manifest_sha256"]
            == release_manifest_digest
        )

        # Each public output is independently restartable at the exact
        # hard-link crash point. Re-entry adopts only the deterministic
        # same-inode pair and never rotates the already published key.
        for index, killed_name in enumerate(
            (
                "production-cutover-operator-trust.v1.json",
                "production-cutover-operator-trust-generation.receipt.json",
            ),
            start=1,
        ):
            crash_root = root / f"public-crash-{index}"
            crash_root.mkdir(mode=0o700)
            crash_command = generation_command(
                tool,
                openssl,
                crash_root,
                credential_id=f"fixture-crash-{index}",
            )
            killed = run(
                crash_command,
                success=False,
                env={
                    **os.environ,
                    "CATS_E13_TRUST_FIXTURE_KILL_AFTER_LINK": killed_name,
                },
            )
            assert killed.returncode < 0
            killed_path = crash_root / killed_name
            assert_interrupted_link_pair(killed_path)
            key_before = (crash_root / "offline-operator-key.pem").read_bytes()
            run(crash_command)
            assert killed_path.stat().st_nlink == 1
            assert not killed_path.with_name(
                f".{killed_path.name}.cats-publish-v1"
            ).exists()
            assert (crash_root / "offline-operator-key.pem").read_bytes() == key_before

        # A foreign final output and an unrecognized multiple-link state both
        # fail closed and remain byte-for-byte untouched.
        foreign = root / "foreign-output"
        foreign.mkdir(mode=0o700)
        foreign_receipt = foreign / verification.name
        foreign_receipt.write_bytes(b"foreign\n")
        foreign_receipt.chmod(0o600)
        foreign_before = foreign_receipt.read_bytes()
        foreign_command = [
            *verify_command[: verify_command.index(str(verification))],
            str(foreign_receipt),
            *verify_command[verify_command.index(str(verification)) + 1 :],
        ]
        run(foreign_command, success=False)
        assert foreign_receipt.read_bytes() == foreign_before

        multiple = root / "multiple-link-output"
        multiple.mkdir(mode=0o700)
        multiple_receipt = multiple / verification.name
        multiple_receipt.write_bytes(verification.read_bytes())
        multiple_receipt.chmod(0o600)
        multiple_link = multiple / "foreign-link"
        os.link(multiple_receipt, multiple_link)
        multiple_before = multiple_receipt.read_bytes()
        multiple_command = [
            *verify_command[: verify_command.index(str(verification))],
            str(multiple_receipt),
            *verify_command[verify_command.index(str(verification)) + 1 :],
        ]
        run(multiple_command, success=False)
        assert multiple_receipt.read_bytes() == multiple_before
        assert multiple_receipt.stat().st_nlink == 2

        wrong_release = common_public(tool, trust, generation)
        wrong_release[wrong_release.index(RELEASE)] = "sha256:" + "0" * 64
        run(wrong_release, success=False)

        noncanonical = root / "noncanonical-trust.json"
        noncanonical.write_bytes(trust.read_bytes() + b"\n")
        noncanonical.chmod(0o644)
        bad_canonical = common_public(tool, noncanonical, generation)
        run(bad_canonical, success=False)

        second = root / "second"
        second.mkdir(mode=0o700)
        second_key = second / "other-key.pem"
        second_trust = second / "production-cutover-operator-trust.v1.json"
        second_generation = second / "production-cutover-operator-trust-generation.receipt.json"
        second_command = [
            sys.executable,
            "-B",
            str(tool),
            "generate",
            "--deployment-id",
            DEPLOYMENT,
            "--release-id",
            RELEASE,
            "--source-commit",
            SOURCE,
            "--credential-id",
            "fixture-other",
            "--aws-partition",
            "aws",
            "--account-id",
            "123456789012",
            "--role-arn",
            "arn:aws:iam::123456789012:role/cats-production-cutover",
            "--private-key-out",
            str(second_key),
            "--trust-out",
            str(second_trust),
            "--generation-receipt-out",
            str(second_generation),
            "--openssl",
            str(openssl),
        ]
        run(second_command)
        mismatch = [
            sys.executable,
            "-B",
            str(tool),
            "verify",
            "--trust-file",
            str(trust),
            "--generation-receipt",
            str(generation),
            "--private-key-file",
            str(second_key),
            "--verification-receipt-out",
            str(second / "production-cutover-operator-trust-verification.receipt.json"),
            "--expected-source-commit",
            SOURCE,
            "--expected-deployment-id",
            DEPLOYMENT,
            "--expected-release-id",
            RELEASE,
            "--openssl",
            str(openssl),
        ]
        run(mismatch, success=False)

    print("production cutover operator trust fixture passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
