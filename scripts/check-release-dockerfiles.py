#!/usr/bin/env python3
"""Check that release Dockerfiles only name real Cargo packages and binaries.

The release images are built once, by hand, on an isolated host. Nothing else
in the gate parses them, so a stale `-p` package name or a renamed binary used
to survive until that build failed tens of minutes in. This check runs from
`quality.sh fast`, where the same mistake costs seconds.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

DOCKERFILES = (
    "deploy/aws/Dockerfile.control-plane",
    "deploy/aws/Dockerfile.gateway",
    "deploy/aws/Dockerfile.worker-artifact",
)

PACKAGE_FLAG = re.compile(r"(?:^|\s)-p\s+(?P<name>[A-Za-z0-9_-]+)")
RELEASE_BINARY = re.compile(r"target/release/(?P<name>[A-Za-z0-9_-]+)")
COPY_INSTRUCTION = re.compile(r"^COPY\s+(?P<rest>.+)$", re.MULTILINE)
# Paths a release stage builds rather than copies from the context.
GENERATED_CONTEXT_PATHS = ("guest-runtime-release.v1",)


def dockerignore_rules(root: Path) -> list[tuple[str, bool]]:
    """Return (regex, is_exception) rules in file order."""
    path = root / ".dockerignore"
    if not path.is_file():
        return []
    rules: list[tuple[str, bool]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        exception = pattern.startswith("!")
        if exception:
            pattern = pattern[1:].strip()
        pattern = pattern.rstrip("/")
        # Docker patterns: `*` stops at a separator, `**` spans them, and a
        # match also covers everything below the matched path.
        expression = ""
        index = 0
        while index < len(pattern):
            character = pattern[index]
            if pattern.startswith("**", index):
                expression += ".*"
                index += 2
            elif character == "*":
                expression += "[^/]*"
                index += 1
            elif character == "?":
                expression += "[^/]"
                index += 1
            else:
                expression += re.escape(character)
                index += 1
        rules.append((f"^{expression}(/.*)?$", exception))
    return rules


def excluded_from_context(relative: str, rules: list[tuple[str, bool]]) -> bool:
    """Apply the rules in order; the last match decides, as Docker does."""
    excluded = False
    for expression, exception in rules:
        if re.match(expression, relative):
            excluded = not exception
    return excluded


def copy_sources(text: str) -> list[str]:
    """Return the context-relative sources of every COPY without --from."""
    sources: list[str] = []
    for match in COPY_INSTRUCTION.finditer(text):
        rest = match.group("rest").strip()
        while rest.endswith("\\"):
            rest = rest[:-1].strip()
        arguments = [word for word in rest.split() if word]
        if any(word.startswith("--from=") for word in arguments):
            continue
        operands = [word for word in arguments if not word.startswith("--")]
        if len(operands) < 2:
            continue
        sources.extend(operands[:-1])
    return sources


def workspace_metadata(root: Path) -> tuple[set[str], set[str]]:
    """Return the workspace's package names and its binary target names."""
    raw = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    metadata = json.loads(raw)
    packages: set[str] = set()
    binaries: set[str] = set()
    for package in metadata["packages"]:
        packages.add(package["name"])
        for target in package["targets"]:
            if "bin" in target["kind"]:
                binaries.add(target["name"])
    return packages, binaries


def check_image_reference_rules(root: Path) -> list[str]:
    """Run the transport verifier's registry-inference rules."""
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            str(root / "deploy/aws/tools/image-transport-fixture.py"),
            "--verifier",
            str(root / "deploy/aws/tools/verify-image-transport.py"),
            "--reference-rules-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return [f"image transport reference rules: {result.stderr.strip()}"]
    return []


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    packages, binaries = workspace_metadata(root)
    ignore_rules = dockerignore_rules(root)
    failures: list[str] = check_image_reference_rules(root)

    for relative in DOCKERFILES:
        path = root / relative
        if not path.is_file():
            failures.append(f"{relative}: missing release Dockerfile")
            continue
        text = path.read_text(encoding="utf-8")
        for match in PACKAGE_FLAG.finditer(text):
            name = match.group("name")
            if name not in packages:
                failures.append(
                    f"{relative}: cargo package {name!r} is not in the workspace"
                )
        for match in RELEASE_BINARY.finditer(text):
            name = match.group("name")
            if name not in binaries:
                failures.append(
                    f"{relative}: release binary {name!r} is not a workspace binary"
                )
        for source in copy_sources(text):
            if source == "." or source.startswith(GENERATED_CONTEXT_PATHS):
                continue
            if not (root / source).exists():
                failures.append(f"{relative}: COPY source {source!r} does not exist")
            elif excluded_from_context(source, ignore_rules):
                failures.append(
                    f"{relative}: COPY source {source!r} is excluded by .dockerignore"
                )

    if failures:
        for failure in sorted(set(failures)):
            print(failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
