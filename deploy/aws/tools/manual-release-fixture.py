#!/usr/bin/env python3
"""Black-box fixture for the manual release verifier."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


WORKER_FILES = {
    "cats",
    "cats-noded",
    "cats-vmm-launcher",
    "cats-blockd",
    "cats-guest-agent",
    "update-guest-seed.sh",
    "require-idle-worker.sh",
    "render-postgres-url.sh",
    "install-guest-runtime-release.sh",
    "validate-node-identity-installation.sh",
    "worker-deployment-transaction.sh",
    "guest-systemd/cats-grow-root.service",
    "guest-systemd/cats-guest-agent.service",
    "guest-systemd/cats-mount-propagation.service",
    "guest-systemd/cats-network.service",
    "cats-worker.service",
    "cats-postgres-url.service",
    "cats-postgres-url.timer",
    "guest-runtime-release.v1/manifest.v1.json",
    "guest-runtime-release.v1/guest-runtime-profile.v1.json",
    "guest-runtime-release.v1/guest/vmlinuz",
    "guest-runtime-release.v1/guest/initramfs.img",
}
WORKER_DIRECTORIES = {
    ".",
    "guest-systemd",
    "guest-runtime-release.v1",
    "guest-runtime-release.v1/guest",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write_member(path: Path, raw: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def make_guest_release(root: Path) -> dict[str, bytes]:
    kernel = b"fixture-kernel\0bytes"
    initramfs = b"fixture-initramfs\0bytes"
    profile = canonical(
        {
            "guest_agent_protocol_version": 1,
            "initramfs_digest": digest(initramfs),
            "kernel_cmdline": "console=ttyS0 root=/dev/vda rw",
            "kernel_digest": digest(kernel),
            "version": 1,
        }
    )
    manifest = canonical(
        {
            "guest_runtime_profile": {
                "path": "guest-runtime-profile.v1.json",
                "sha256": digest(profile),
                "size_bytes": len(profile),
            },
            "initramfs": {
                "path": "guest/initramfs.img",
                "sha256": digest(initramfs),
                "size_bytes": len(initramfs),
            },
            "kernel": {
                "path": "guest/vmlinuz",
                "sha256": digest(kernel),
                "size_bytes": len(kernel),
            },
            "version": 1,
        }
    )
    write_member(root / "manifest.v1.json", manifest)
    write_member(root / "guest-runtime-profile.v1.json", profile)
    write_member(root / "guest/vmlinuz", kernel)
    write_member(root / "guest/initramfs.img", initramfs)
    return {
        "kernel": kernel,
        "initramfs": initramfs,
        "profile": profile,
        "manifest": manifest,
    }


def run_verifier(
    verifier: Path,
    workspace: Path,
    output: Path,
    *,
    expect_success: bool,
) -> subprocess.CompletedProcess[bytes]:
    shared = workspace / "shared"
    control = workspace / "control"
    bundle = workspace / "cats-worker.tar.zst"
    source_input = workspace / "Cargo.lock"
    command = [
        sys.executable,
        str(verifier),
        "--shared-guest-runtime",
        str(shared),
        "--control-root",
        str(control),
        "--worker-bundle",
        str(bundle),
        "--control-image-reference",
        "registry.example/cats/control-plane:fixture",
        "--control-image-digest",
        "sha256:" + "1" * 64,
        "--control-image-config-digest",
        "sha256:" + "2" * 64,
        "--control-image-registry-verified",
        "false",
        "--source-commit",
        "3" * 40,
        "--source-tree",
        "4" * 40,
        "--source-fingerprint",
        "sha256:" + "5" * 64,
        "--input-file",
        f"cargo_lock={source_input}",
        "--output",
        str(output),
    ]
    result = subprocess.run(command, check=False, capture_output=True)
    if (result.returncode == 0) != expect_success:
        raise AssertionError(
            f"unexpected verifier exit {result.returncode}\n"
            f"stdout:\n{result.stdout.decode(errors='replace')}\n"
            f"stderr:\n{result.stderr.decode(errors='replace')}"
        )
    return result


def package_worker(
    root: Path,
    *,
    worker_files: set[str] | None = None,
    add_traversal: bool = False,
) -> None:
    worker = root / "worker"
    selected_files = WORKER_FILES if worker_files is None else worker_files
    tar_path = root / "worker.tar"
    bundle = root / "cats-worker.tar.zst"
    with tarfile.open(tar_path, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in sorted(WORKER_DIRECTORIES, key=lambda path: (path.count("/"), path)):
            member = tarfile.TarInfo(relative)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            member.uid = 0
            member.gid = 0
            member.mtime = 0
            archive.addfile(member)
        for relative in sorted(selected_files):
            raw = (worker / relative).read_bytes()
            member = tarfile.TarInfo(relative)
            member.mode = (worker / relative).stat().st_mode & 0o777
            member.uid = 0
            member.gid = 0
            member.mtime = 0
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        if add_traversal:
            member = tarfile.TarInfo("../escape")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            member.mode = 0o777
            member.uid = 0
            member.gid = 0
            member.mtime = 0
            archive.addfile(member)
    subprocess.run(
        ["zstd", "--quiet", "--force", "-19", "-o", str(bundle), str(tar_path)],
        check=True,
    )
    tar_path.unlink()


def prepare_workspace(root: Path) -> dict[str, bytes]:
    shared = root / "shared"
    members = make_guest_release(shared)
    worker_release = root / "worker/guest-runtime-release.v1"
    shutil.copytree(shared, worker_release)
    executable = {
        "cats",
        "cats-noded",
        "cats-vmm-launcher",
        "cats-blockd",
        "cats-guest-agent",
        "update-guest-seed.sh",
        "require-idle-worker.sh",
        "render-postgres-url.sh",
        "install-guest-runtime-release.sh",
        "validate-node-identity-installation.sh",
    }
    for relative in WORKER_FILES - {
        "guest-runtime-release.v1/manifest.v1.json",
        "guest-runtime-release.v1/guest-runtime-profile.v1.json",
        "guest-runtime-release.v1/guest/vmlinuz",
        "guest-runtime-release.v1/guest/initramfs.img",
    }:
        mode = 0o755 if relative in executable else 0o644
        write_member(root / "worker" / relative, f"fixture-{relative}\n".encode(), mode)
    package_worker(root)
    write_member(root / "Cargo.lock", b"fixture-lockfile")
    control_release = root / "control/opt/cats/release"
    write_member(control_release / "guest-runtime-release-manifest.v1.json", members["manifest"])
    write_member(control_release / "guest-runtime-profile.v1.json", members["profile"])
    return members


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "--verifier":
        print("usage: manual-release-fixture.py --verifier PATH", file=sys.stderr)
        return 2
    verifier = Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory(prefix="cats-release-fixture-") as temporary:
        root = Path(temporary)
        members = prepare_workspace(root)
        output = root / "release-manifest.v1.json"
        result = run_verifier(verifier, root, output, expect_success=True)
        raw = output.read_bytes()
        parsed = json.loads(raw)
        assert canonical(parsed) == raw
        expected_release_id = digest(
            b"cats.release.guest-runtime-manifest.v1\0" + members["manifest"]
        )
        assert parsed["guest_runtime"]["release_id"] == expected_release_id
        assert parsed["source"] == {
            "commit": "3" * 40,
            "fingerprint": "sha256:" + "5" * 64,
            "tree": "4" * 40,
        }
        assert parsed["artifacts"]["control_plane"]["registry_verified"] is False
        assert b"guest_runtime_release_id=" + expected_release_id.encode() in result.stdout

        # The verifier never overwrites its canonical receipt.
        run_verifier(verifier, root, output, expect_success=False)
        assert output.read_bytes() == raw

        output.unlink()
        write_member(
            root / "control/opt/cats/release/guest-runtime-profile.v1.json",
            members["profile"] + b"\n",
        )
        mismatch = run_verifier(verifier, root, output, expect_success=False)
        assert b"not byte-identical" in mismatch.stderr
        assert not output.exists()

        write_member(
            root / "control/opt/cats/release/guest-runtime-profile.v1.json",
            members["profile"],
        )

        cats = root / "worker/cats"
        cats.unlink()
        package_worker(root, worker_files=WORKER_FILES - {"cats"})
        missing_cats = run_verifier(verifier, root, output, expect_success=False)
        assert b"file set differs" in missing_cats.stderr
        assert b"cats" in missing_cats.stderr
        assert not output.exists()

        write_member(cats, b"fixture-cats\n", 0o755)
        unexpected = root / "worker/unexpected-worker-file"
        write_member(unexpected, b"unexpected\n", 0o644)
        package_worker(root, worker_files=WORKER_FILES | {"unexpected-worker-file"})
        extra_member = run_verifier(verifier, root, output, expect_success=False)
        assert b"file set differs" in extra_member.stderr
        assert b"unexpected-worker-file" in extra_member.stderr
        assert not output.exists()
        unexpected.unlink()

        cats.chmod(0o644)
        package_worker(root)
        wrong_cats_mode = run_verifier(verifier, root, output, expect_success=False)
        assert b"member mode is not 0755: cats" in wrong_cats_mode.stderr
        assert not output.exists()
        cats.chmod(0o755)

        write_member(root / "worker/guest-runtime-release.v1/guest/vmlinuz", b"corrupt")
        package_worker(root)
        corrupt = run_verifier(verifier, root, output, expect_success=False)
        assert b"wrong size" in corrupt.stderr or b"wrong digest" in corrupt.stderr
        assert not output.exists()

        package_worker(root, add_traversal=True)
        traversal = run_verifier(verifier, root, output, expect_success=False)
        assert b"unsafe path" in traversal.stderr
        assert not output.exists()
        assert not (root.parent / "escape").exists()

    print("manual release verifier fixture passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
