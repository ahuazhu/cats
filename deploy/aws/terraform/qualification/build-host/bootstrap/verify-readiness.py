#!/usr/bin/env python3
import json
import hashlib
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile


IDENTITY_PATH = pathlib.Path("/etc/cats-build/identity.json")
READINESS_PATH = pathlib.Path("/var/lib/cats-build/readiness-v1.json")
CHECKOUT_PATH = pathlib.Path("/usr/local/bin/cats-checkout-exact-sha")
SOURCE_PARENT = pathlib.Path("/srv/cats-build")
TARGET_PARENT = SOURCE_PARENT / "target"
RECEIPT_DIR = pathlib.Path("/var/lib/cats-build/source-receipts")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def active(unit: str) -> bool:
    return run("systemctl", "is-active", "--quiet", unit, check=False).returncode == 0


def fail(message: str) -> None:
    raise RuntimeError(message)


def root_owned_mode(path: pathlib.Path, mode: int) -> None:
    file_stat = path.stat()
    if file_stat.st_uid != 0 or stat.S_IMODE(file_stat.st_mode) != mode:
        fail(f"unsafe ownership or mode: {path}")


def buildkit_worker_uses_cni(workers: str) -> bool:
    label = "org.mobyproject.buildkit.worker.network:"
    return [line.split()[1:] for line in workers.splitlines() if line.split()[:1] == [label]] == [["cni"]]


def main() -> int:
    identity = json.loads(IDENTITY_PATH.read_text(encoding="utf-8"))
    readiness = json.loads(READINESS_PATH.read_text(encoding="utf-8"))

    if readiness.get("schema_version") != 1 or readiness.get("status") != "ready":
        fail("readiness document is not schema v1 ready")
    for field in ("account_id", "region", "namespace", "cell_id"):
        if readiness.get("qualification", {}).get(field) != identity[field]:
            fail(f"qualification identity mismatch: {field}")
    for field in ("ami_id", "instance_type"):
        if readiness.get("host", {}).get(field) != identity[field]:
            fail(f"host identity mismatch: {field}")
    if readiness.get("host", {}).get("architecture") != "x86_64":
        fail("host architecture is not x86_64")

    expected_source_policy = {
        "build_host_github_credential": False,
        "bundle_digest_required": True,
        "bundle_prefix": "source/bundles/sha256/",
        "delivery_mode": "controller-content-addressed-git-bundle-v1",
        "dirty_tree_allowed": False,
        "exact_commit_sha_required": True,
        "git_lfs_allowed": False,
        "gitlinks_allowed": False,
        "manifest_digest_required": True,
        "manifest_prefix": "source/manifests/sha256/",
        "ref_allowed": False,
        "repository": "https://github.com/ahuazhu/cats.git",
        "root_verified_and_published": True,
        "source_bucket": identity["source_bucket"],
        "source_kms_alias_arn": identity["source_kms_alias_arn"],
        "submodules_allowed": False,
    }
    if readiness.get("source_policy") != expected_source_policy:
        fail("source delivery policy differs from the controller-bundle contract")

    for field in ("toolchain_lock_sha256",):
        if not SHA256.fullmatch(readiness.get("bootstrap", {}).get(field, "")):
            fail(f"invalid bootstrap digest: {field}")
    installed_components = {
        "bootstrap": pathlib.Path("/usr/local/sbin/cats-build-bootstrap"),
        "checkout": CHECKOUT_PATH,
        "imds_guard": pathlib.Path("/usr/local/sbin/cats-build-imds-guard"),
        "immutable_receipt": pathlib.Path("/usr/local/lib/cats-build/immutable-receipt.sh"),
        "publish": pathlib.Path("/usr/local/bin/cats-publish-content-addressed"),
        "readiness": pathlib.Path("/usr/local/bin/cats-verify-build-host-readiness"),
        "run_build": pathlib.Path("/usr/local/sbin/cats-run-build"),
        "stage_output": pathlib.Path("/usr/local/libexec/cats-build/stage-build-output"),
        "toolchain_lock": pathlib.Path("/opt/cats-build/toolchain-lock-v1.json"),
    }
    components = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in installed_components.items()
    }
    payload = json.dumps(components, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(payload).hexdigest() != identity.get("bootstrap_payload_sha256"):
        fail("bootstrap component digest map differs from the reviewed identity")
    if readiness.get("bootstrap", {}).get("payload_sha256") != identity.get(
        "bootstrap_payload_sha256"
    ):
        fail("readiness bootstrap payload identity mismatch")
    publication = readiness.get("publication", {})
    if publication.get("bucket") != identity.get("artifact_bucket"):
        fail("artifact bucket identity mismatch")
    if publication.get("kms_alias_arn") != identity.get("artifact_kms_alias_arn"):
        fail("artifact KMS identity mismatch")
    if publication.get("prefixes") != ["artifacts/sha256/", "evidence/sha256/"]:
        fail("artifact publication prefixes differ from the contract")

    root_owned_mode(CHECKOUT_PATH, 0o755)
    root_owned_mode(SOURCE_PARENT, 0o755)
    root_owned_mode(RECEIPT_DIR, 0o755)
    root_owned_mode(TARGET_PARENT, 0o755)
    run(
        "runuser",
        "-u",
        "cats-build",
        "--",
        "bash",
        "-euc",
        "test ! -w /srv/cats-build/target; test ! -w /srv/cats-build; "
        "test ! -w /var/lib/cats-build/source-receipts",
    )
    for path in (
        pathlib.Path("/opt/cats-build/cargo/bin/cargo"),
        pathlib.Path("/opt/cats-build/cargo/bin/cargo-deny"),
        pathlib.Path("/opt/cats-build/cargo/bin/cargo-machete"),
        pathlib.Path("/opt/cats-build/rustup"),
    ):
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o222:
            fail(f"trusted toolchain path is writable: {path}")
    groups = run("id", "-nG", "cats-build").stdout.split()
    if "docker" in groups:
        fail("cats-build must not belong to the docker group")

    if not active("docker.service") or not active("buildkit.service"):
        fail("container build services are not active")
    workers = run(
        "/usr/local/bin/buildctl",
        "--addr",
        "unix:///run/buildkit/buildkitd.sock",
        "debug",
        "workers",
        "--verbose",
    ).stdout
    if not buildkit_worker_uses_cni(workers):
        fail("BuildKit worker network is not cni")
    if run(
        "runuser",
        "-u",
        "cats-build",
        "--",
        "/usr/local/bin/buildctl",
        "--addr",
        "unix:///run/buildkit/buildkitd.sock",
        "debug",
        "workers",
        check=False,
    ).returncode == 0:
        fail("cats-build can access the root BuildKit daemon")
    if run(
        "runuser",
        "-u",
        "cats-build",
        "--",
        "curl",
        "--fail",
        "--silent",
        "--unix-socket",
        "/run/docker.sock",
        "http://localhost/_ping",
        check=False,
    ).returncode == 0:
        fail("cats-build can access the root Docker daemon")

    with tempfile.TemporaryDirectory(prefix="cats-buildkit-network-") as probe_dir:
        probe_path = pathlib.Path(probe_dir)
        shutil.copy2("/usr/local/libexec/cats-build/imds-probe", probe_path / "imds-probe")
        (probe_path / "Dockerfile.positive").write_text(
            'FROM scratch\nCOPY imds-probe /imds-probe\nRUN ["/imds-probe", "offline"]\n',
            encoding="utf-8",
        )
        (probe_path / "Dockerfile.negative").write_text(
            'FROM scratch\nCOPY imds-probe /imds-probe\nRUN ["/imds-probe"]\n',
            encoding="utf-8",
        )
        common = (
            "/usr/local/bin/buildctl",
            "--addr",
            "unix:///run/buildkit/buildkitd.sock",
            "build",
            "--frontend",
            "dockerfile.v0",
            "--local",
            f"context={probe_dir}",
            "--local",
            f"dockerfile={probe_dir}",
        )
        run(*common, "--opt", "filename=Dockerfile.positive")
        if run(
            *common,
            "--opt",
            "filename=Dockerfile.negative",
            check=False,
        ).returncode == 0:
            fail("a real BuildKit RUN can access IMDS")

    if not active("cats-build-imds-guard.service"):
        fail("IMDS isolation service is not active")
    run("iptables", "-w", "-C", "OUTPUT", "-m", "owner", "--uid-owner", "2000", "-d", "169.254.169.254/32", "-j", "REJECT")
    run("iptables", "-w", "-C", "FORWARD", "-d", "169.254.169.254/32", "-j", "REJECT")
    root_token = run(
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--request",
        "PUT",
        "--header",
        "X-aws-ec2-metadata-token-ttl-seconds: 60",
        "http://169.254.169.254/latest/api/token",
    ).stdout
    if not root_token:
        fail("root IMDS known-positive probe returned no token")
    if run(
        "runuser",
        "-u",
        "cats-build",
        "--",
        "curl",
        "--max-time",
        "2",
        "--fail",
        "--silent",
        "--request",
        "PUT",
        "--header",
        "X-aws-ec2-metadata-token-ttl-seconds: 60",
        "http://169.254.169.254/latest/api/token",
        check=False,
    ).returncode == 0:
        fail("cats-build can access IMDS")

    if not active("chrony.service"):
        fail("AWS time synchronization is not active")
    if not (
        active("snap.amazon-ssm-agent.amazon-ssm-agent.service")
        or active("amazon-ssm-agent.service")
    ):
        fail("SSM agent is not active")
    print(json.dumps(readiness, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"not ready: {error}", file=sys.stderr)
        raise SystemExit(1) from error
