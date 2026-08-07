#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import sys


def option(arguments: list[str], name: str) -> str:
    return arguments[arguments.index(name) + 1]


def main() -> int:
    arguments = sys.argv[1:]
    if arguments[:2] == ["sts", "get-caller-identity"]:
        print(os.environ["FAKE_AWS_ACCOUNT_ID"])
        return 0
    if arguments[:2] == ["kms", "describe-key"]:
        print(os.environ["FAKE_AWS_KMS_KEY_ARN"])
        return 0
    if arguments[:2] not in (["s3api", "put-object"], ["s3api", "head-object"]):
        raise RuntimeError(f"unexpected fake AWS call: {arguments!r}")

    key = option(arguments, "--key")
    record_path = pathlib.Path(os.environ["FAKE_AWS_STORE"]) / hashlib.sha256(
        key.encode()
    ).hexdigest()
    if arguments[1] == "put-object":
        body = pathlib.Path(option(arguments, "--body")).read_bytes()
        record = {
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode(),
            "ContentLength": len(body),
            "ServerSideEncryption": option(arguments, "--server-side-encryption"),
            "SSEKMSKeyId": os.environ["FAKE_AWS_KMS_KEY_ARN"],
            "VersionId": "version-" + hashlib.sha256(body).hexdigest()[:24],
        }
        try:
            descriptor = os.open(record_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return 1
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True)
        print(json.dumps(record, sort_keys=True))
        return 0

    print(record_path.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
