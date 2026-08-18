#!/usr/bin/env python3
"""Verify every release-bound value before a production release switch.

A release switch changes far more than a commit: the control schema, two
independent PostgreSQL DSNs, three Route v2 secrets, the ObjectWrite Gateway's
server certificate, the guest config digest baked into every placement policy,
two image digests, the worker bundle, and the account/workspace the
qualification binding names. Each of those is checked exactly at use time and
fails closed, so a single stale copy costs one production round to discover.

This tool answers "is everything consistent?" offline, in seconds, before the
first production change. It only reads; it never mutates.

Every check prints PASS or FAIL with the two values it compared, so a failure
names the exact file to fix.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class Report:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.skipped: list[str] = []

    def check(self, name: str, ok: bool, detail: str) -> bool:
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
        if not ok:
            self.failures.append(name)
        return ok

    def skip(self, name: str, why: str) -> None:
        print(f"SKIP  {name}: {why}")
        self.skipped.append(name)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def dsn_schema(dsn: str) -> str | None:
    """The search_path a control DSN pins, or None when it pins none."""
    query = urllib.parse.urlparse(dsn.strip()).query
    options = urllib.parse.parse_qs(query).get("options", [])
    for option in options:
        match = re.search(r"-c\s*search_path\s*=\s*([A-Za-z0-9_]+)", option)
        if match:
            return match.group(1)
    return None


def openssl(args: list[str], openssl_bin: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [openssl_bin, *args], capture_output=True, text=True, check=False
    )


def check_commit(report: Report, commit: str) -> None:
    report.check(
        "exact-commit is a 40-hex sha",
        bool(COMMIT_RE.match(commit)),
        commit,
    )


def check_images(report: Report, manifest: Path, tfvars: Path) -> None:
    """Both deployed image references must be the registry-verified digests."""
    published = read_json(manifest)
    digests: dict[str, str] = {}
    verified: dict[str, bool] = {}

    def walk(node: object) -> None:
        if isinstance(node, dict):
            reference = node.get("image_reference")
            digest = node.get("image_digest")
            if isinstance(reference, str) and isinstance(digest, str):
                role = "gateway" if "gateway-" in reference else "control"
                digests[role] = digest
                verified[role] = bool(node.get("registry_verified"))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(published)
    for role in ("control", "gateway"):
        report.check(
            f"{role} image is registry-verified",
            verified.get(role, False),
            f"{digests.get(role, 'missing')}",
        )

    text = tfvars.read_text()
    for variable, role in (
        ("control_plane_image", "control"),
        ("gateway_image", "gateway"),
        ("object_write_gateway_image", "control"),
    ):
        match = re.search(rf"^{variable}\s*=\s*\"([^\"]+)\"", text, re.M)
        if not match:
            report.check(f"{variable} is set", False, "absent from tfvars")
            continue
        expected = digests.get(role)
        report.check(
            f"{variable} matches the {role} release digest",
            expected is not None and match.group(1).endswith(expected),
            f"{match.group(1).rsplit('@', 1)[-1]} vs {expected}",
        )


def check_schema(report: Report, schema: str, tfvars: list[Path], dsns: list[Path]) -> None:
    """The schema has one authored home; every copy must agree with it."""
    for path in tfvars:
        text = path.read_text()
        for variable in ("control_postgres_schema",):
            match = re.search(rf"^{variable}\s*=\s*\"([^\"]+)\"", text, re.M)
            if match:
                report.check(
                    f"{path.name}:{variable}",
                    match.group(1) == schema,
                    f"{match.group(1)} vs {schema}",
                )
    for path in dsns:
        found = dsn_schema(path.read_text())
        report.check(
            f"{path.name} pins the target schema",
            found == schema,
            f"{found} vs {schema}",
        )


def check_guest_digest(
    report: Report, profile: Path, policies: list[Path], digest_tool: list[str] | None
) -> None:
    """The guest config digest changes every release; policies must be rebuilt."""
    if digest_tool is None:
        report.skip("guest config digest", "no --guest-digest-command given")
        return
    result = subprocess.run(
        [*digest_tool, str(profile)], capture_output=True, text=True, check=False
    )
    computed = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if not SHA256_RE.match(computed):
        report.check(
            "guest config digest recomputes",
            False,
            f"tool produced {computed!r} rc={result.returncode}",
        )
        return
    report.check("guest config digest recomputes", True, computed)
    for path in policies:
        stored = read_json(path).get("capabilities", {}).get("guest_config_digest")
        report.check(
            f"{path.name} carries the release digest",
            stored == computed,
            f"{stored} vs {computed}",
        )


def check_gateway_certificate(
    report: Report, leaf: Path | None, root: Path | None, openssl_bin: str
) -> None:
    """The gateway leaf must be issued by *this* release's Route v2 root."""
    if leaf is None or root is None:
        report.skip("gateway server certificate", "no --gateway-leaf/--route-v2-root")
        return
    verify = openssl(["verify", "-CAfile", str(root), str(leaf)], openssl_bin)
    report.check(
        "gateway leaf verifies against the material root",
        verify.returncode == 0,
        (verify.stdout + verify.stderr).strip().splitlines()[-1]
        if (verify.stdout or verify.stderr)
        else "no output",
    )


def check_worker_bundle(report: Report, bundle: Path | None, expected: str | None) -> None:
    if bundle is None or expected is None:
        report.skip("worker bundle digest", "no --worker-bundle/--worker-bundle-sha256")
        return
    import hashlib

    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    want = expected.removeprefix("sha256:")
    report.check(
        "worker bundle digest matches the release",
        digest == want,
        f"{digest[:16]}… vs {want[:16]}…",
    )


def check_replay_cache(report: Report, cache: Path | None) -> None:
    """A settled replay record makes an admin write silently do nothing.

    The record key does not include the control database, so a byte-identical
    request against a fresh schema replays the previous release's outcome and
    reports success without writing anything (issue #322).
    """
    if cache is None:
        report.skip("CLI replay cache", "no --cli-authority-cache")
        return
    if not cache.is_dir():
        report.check("CLI replay cache is clear", True, f"{cache} is absent")
        return
    settled = sorted(cache.glob("*.settled.json"))
    report.check(
        "CLI replay cache is clear of settled records",
        not settled,
        f"{len(settled)} settled record(s) would replay instead of writing",
    )


def check_qualification_scope(
    report: Report, binding: Path | None, accounts: Path | None
) -> None:
    """The qualification binding must name a workspace the target schema has."""
    if binding is None:
        report.skip("qualification scope", "no --qualification-binding")
        return
    bound = read_json(binding)
    account, workspace = bound.get("cats_account_id"), bound.get("workspace_id")
    if accounts is None:
        report.skip(
            "qualification scope exists",
            f"binding names {account}/{workspace}; pass --target-scope to verify",
        )
        return
    actual = read_json(accounts)
    report.check(
        "qualification binding names the target account",
        account == actual.get("account_id"),
        f"{account} vs {actual.get('account_id')}",
    )
    report.check(
        "qualification binding names the target workspace",
        workspace == actual.get("workspace_id"),
        f"{workspace} vs {actual.get('workspace_id')}",
    )


def check_release_binding(report: Report, commit: str, trusts: list[Path]) -> None:
    """Every release-bound trust bundle must name this exact commit."""
    for path in trusts:
        document = read_json(path)
        found = document.get("source_commit_sha") or document.get("release_commit_sha")
        report.check(
            f"{path.name} binds the exact commit",
            found == commit,
            f"{found} vs {commit}",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exact-commit", required=True)
    parser.add_argument("--target-schema", required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--application-tfvars", type=Path, required=True)
    parser.add_argument("--infrastructure-tfvars", type=Path)
    parser.add_argument("--control-dsn-file", type=Path, action="append", default=[])
    parser.add_argument("--guest-runtime-profile", type=Path)
    parser.add_argument("--guest-digest-command")
    parser.add_argument("--placement-policy", type=Path, action="append", default=[])
    parser.add_argument("--gateway-leaf", type=Path)
    parser.add_argument("--route-v2-root", type=Path)
    parser.add_argument("--worker-bundle", type=Path)
    parser.add_argument("--worker-bundle-sha256")
    parser.add_argument("--cli-authority-cache", type=Path)
    parser.add_argument("--qualification-binding", type=Path)
    parser.add_argument("--target-scope", type=Path)
    parser.add_argument("--release-bound-trust", type=Path, action="append", default=[])
    parser.add_argument("--openssl", default="/usr/bin/openssl")
    args = parser.parse_args()

    report = Report()
    check_commit(report, args.exact_commit)
    check_images(report, args.release_manifest, args.application_tfvars)
    tfvars = [args.application_tfvars]
    if args.infrastructure_tfvars is not None:
        tfvars.append(args.infrastructure_tfvars)
    check_schema(report, args.target_schema, tfvars, args.control_dsn_file)
    if args.guest_runtime_profile is not None:
        check_guest_digest(
            report,
            args.guest_runtime_profile,
            args.placement_policy,
            args.guest_digest_command.split() if args.guest_digest_command else None,
        )
    else:
        report.skip("guest config digest", "no --guest-runtime-profile")
    check_gateway_certificate(report, args.gateway_leaf, args.route_v2_root, args.openssl)
    check_worker_bundle(report, args.worker_bundle, args.worker_bundle_sha256)
    check_replay_cache(report, args.cli_authority_cache)
    check_qualification_scope(report, args.qualification_binding, args.target_scope)
    check_release_binding(report, args.exact_commit, args.release_bound_trust)

    print()
    if report.failures:
        print(f"REFUSED: {len(report.failures)} inconsistent value(s):")
        for name in report.failures:
            print(f"  - {name}")
        return 1
    print(f"READY: every checked value is consistent ({len(report.skipped)} skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
