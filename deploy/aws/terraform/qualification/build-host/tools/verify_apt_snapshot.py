#!/usr/bin/env python3
"""Positive proof that the locked Ubuntu snapshot and package versions exist."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "bootstrap" / "toolchain-lock-v1.json"
SNAPSHOT_ROOT = "https://snapshot.ubuntu.com/ubuntu"
SUITES = ("noble", "noble-updates", "noble-security")
COMPONENTS = ("main", "universe")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "cats-qualification-snapshot-probe/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            raise RuntimeError(f"{url}: expected HTTP 200, got {response.status}")
        return response.read()


def package_versions(packages: bytes) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for paragraph in packages.decode("utf-8").split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if ": " in line and not line.startswith((" ", "\t")):
                key, value = line.split(": ", 1)
                fields[key] = value
        if "Package" in fields and "Version" in fields:
            found.add((fields["Package"], fields["Version"]))
    return found


def main() -> int:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    apt = lock["apt_snapshot"]
    snapshot_id = apt["snapshot_id"]
    expected_indexes = apt["index_sha256"]
    expected = {(name, version) for name, version in apt["packages"].items()}
    observed: set[tuple[str, str]] = set()
    proof: dict[str, object] = {
        "schema_version": 1,
        "snapshot_id": snapshot_id,
        "indexes": [],
    }

    for suite in SUITES:
        inrelease_url = f"{SNAPSHOT_ROOT}/{snapshot_id}/dists/{suite}/InRelease"
        inrelease = fetch(inrelease_url)
        inrelease_key = f"{suite}/InRelease"
        inrelease_sha256 = hashlib.sha256(inrelease).hexdigest()
        if inrelease_sha256 != expected_indexes[inrelease_key]:
            raise RuntimeError(f"{inrelease_key}: locked digest differs from fetched index")
        proof["indexes"].append(
            {
                "kind": "InRelease",
                "suite": suite,
                "sha256": inrelease_sha256,
            }
        )
        for component in COMPONENTS:
            packages_url = (
                f"{SNAPSHOT_ROOT}/{snapshot_id}/dists/{suite}/"
                f"{component}/binary-amd64/Packages.gz"
            )
            compressed = fetch(packages_url)
            packages_key = f"{suite}/{component}/binary-amd64/Packages.gz"
            packages_sha256 = hashlib.sha256(compressed).hexdigest()
            if packages_sha256 != expected_indexes[packages_key]:
                raise RuntimeError(f"{packages_key}: locked digest differs from fetched index")
            observed.update(package_versions(gzip.decompress(compressed)))
            proof["indexes"].append(
                {
                    "component": component,
                    "kind": "Packages.gz",
                    "sha256": packages_sha256,
                    "suite": suite,
                }
            )

    missing = sorted(expected - observed)
    if missing:
        raise RuntimeError(f"locked packages absent from snapshot: {missing}")
    proof["packages"] = [
        {"name": name, "version": version} for name, version in sorted(expected)
    ]
    proof["status"] = "verified"
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
