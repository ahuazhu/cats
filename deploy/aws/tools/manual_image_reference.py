#!/usr/bin/env python3
"""Canonicalize manual-release image tags and reject alias collisions."""

from __future__ import annotations

import re
import sys


class ImageReferenceError(ValueError):
    pass


_REPOSITORY_COMPONENT = re.compile(
    r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*\Z"
)
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_REGISTRY = re.compile(
    r"(?:localhost|(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?))(?:\:[0-9]{1,5})?\Z"
)


def canonical_image_tag(reference: str) -> str:
    if (
        not reference
        or len(reference) > 1024
        or "@" in reference
        or any(character.isspace() or ord(character) < 0x20 for character in reference)
    ):
        raise ImageReferenceError("image reference must be a bounded tag reference without @")
    slash = reference.rfind("/")
    colon = reference.rfind(":")
    if colon > slash:
        repository, tag = reference[:colon], reference[colon + 1 :]
    else:
        repository, tag = reference, "latest"
    if not repository or _TAG.fullmatch(tag) is None:
        raise ImageReferenceError("image reference has an invalid or missing repository/tag")

    components = repository.split("/")
    if any(not component for component in components):
        raise ImageReferenceError("image reference contains an empty repository component")
    first = components[0]
    if "." in first or ":" in first or first.lower() == "localhost":
        registry = first.lower()
        path = components[1:]
    else:
        registry = "docker.io"
        path = components
    if registry.endswith(":443"):
        registry = registry[:-4]
    if registry in {"index.docker.io", "registry-1.docker.io"}:
        registry = "docker.io"
    if _REGISTRY.fullmatch(registry) is None or not path:
        raise ImageReferenceError("image reference has an invalid registry/repository")
    if registry == "docker.io" and len(path) == 1:
        path.insert(0, "library")
    if any(_REPOSITORY_COMPONENT.fullmatch(component) is None for component in path):
        raise ImageReferenceError("image repository components must be canonical lowercase names")
    return f"{registry}/{'/'.join(path)}:{tag}"


def require_distinct_image_tags(*references: str) -> tuple[str, ...]:
    if len(references) < 2:
        raise ImageReferenceError("at least two image references are required")
    canonical = tuple(canonical_image_tag(reference) for reference in references)
    if len(set(canonical)) != len(canonical):
        raise ImageReferenceError(
            "production image references must resolve to distinct mutable tags"
        )
    return canonical


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: manual_image_reference.py IMAGE_TAG IMAGE_TAG [IMAGE_TAG ...]",
            file=sys.stderr,
        )
        return 2
    try:
        require_distinct_image_tags(*sys.argv[1:])
    except ImageReferenceError as error:
        print(f"manual image reference validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
