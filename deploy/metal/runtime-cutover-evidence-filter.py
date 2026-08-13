#!/usr/bin/env python3
"""Bound and redact runtime-cutover evidence without retaining raw command output."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from typing import Any, BinaryIO


SENSITIVE_NAMES = (
    "authorization",
    "cookie",
    "password",
    "private_key",
    "private-key",
    "raw_body",
    "request_body",
    "response_body",
    "secret",
    "session",
    "token",
    "x-api-key",
)
PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----", re.IGNORECASE)
PRIVATE_KEY_END = re.compile(r"-----END [^-]*PRIVATE KEY-----", re.IGNORECASE)
BEARER = re.compile(r"\b(?:Bearer|Basic)\s+\S+", re.IGNORECASE)
URL_CREDENTIALS = re.compile(r"([a-z][a-z0-9+.-]*://)[^/@\s]+@", re.IGNORECASE)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")


class BoundedOutput:
    def __init__(self, maximum: int) -> None:
        marker = b"\n[TRUNCATED: middle omitted; first/latest retained]\n"
        self.maximum = maximum
        self.marker = marker
        self.first_limit = max(1, (maximum - len(marker)) // 2)
        self.tail_limit = max(1, maximum - len(marker) - self.first_limit)
        self.first = bytearray()
        self.tail: deque[bytes] = deque()
        self.tail_size = 0
        self.total = 0

    def add(self, value: str) -> None:
        data = value.encode("utf-8", errors="replace")
        self.total += len(data)
        if len(self.first) < self.first_limit:
            take = min(self.first_limit - len(self.first), len(data))
            self.first.extend(data[:take])
            data = data[take:]
        if data:
            self.tail.append(data)
            self.tail_size += len(data)
            while self.tail_size > self.tail_limit and self.tail:
                excess = self.tail_size - self.tail_limit
                oldest = self.tail[0]
                if len(oldest) <= excess:
                    self.tail.popleft()
                    self.tail_size -= len(oldest)
                else:
                    self.tail[0] = oldest[excess:]
                    self.tail_size -= excess

    def render(self) -> bytes:
        tail = b"".join(self.tail)
        if self.total <= self.maximum:
            return bytes(self.first) + tail
        return bytes(self.first) + self.marker + tail


def sensitive_name(value: str) -> bool:
    lowered = value.lower().replace("-", "_")
    return any(name.replace("-", "_") in lowered for name in SENSITIVE_NAMES)


def filter_text(stream: BinaryIO, maximum: int) -> int:
    output = BoundedOutput(maximum)
    private_key = False
    oversized = False
    while True:
        raw = stream.readline(4097)
        if not raw:
            break
        complete = raw.endswith(b"\n")
        text = raw.decode("utf-8", errors="replace")
        if private_key:
            if PRIVATE_KEY_END.search(text):
                private_key = False
            continue
        if oversized:
            if complete:
                oversized = False
            continue
        if not complete and len(raw) == 4097:
            output.add("[REDACTED oversized line]\n")
            oversized = True
            continue
        if PRIVATE_KEY_BEGIN.search(text):
            output.add("[REDACTED private key block]\n")
            private_key = not bool(PRIVATE_KEY_END.search(text))
            continue
        if sensitive_name(text):
            output.add("[REDACTED sensitive line]\n")
            continue
        text = BEARER.sub("[REDACTED]", text)
        text = URL_CREDENTIALS.sub(r"\1[REDACTED]@", text)
        text = AWS_ACCESS_KEY.sub("[REDACTED]", text)
        output.add(text)
    sys.stdout.buffer.write(output.render())
    return 0


def validate_inventory(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if sensitive_name(str(key)):
                raise ValueError("inventory contains a sensitive field name")
            validate_inventory(nested)
    elif isinstance(value, list):
        for nested in value:
            validate_inventory(nested)
    elif isinstance(value, str):
        if PRIVATE_KEY_BEGIN.search(value) or BEARER.search(value) or AWS_ACCESS_KEY.search(value):
            raise ValueError("inventory contains a sensitive string value")


def filter_inventory(stream: BinaryIO, maximum: int) -> int:
    raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("inventory exceeds the evidence bound")
    value = json.loads(raw.decode("utf-8"))
    validate_inventory(value)
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    sys.stdout.write(encoded + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("text", "inventory"), required=True)
    parser.add_argument("--max-bytes", type=int, required=True)
    arguments = parser.parse_args()
    if not 256 <= arguments.max_bytes <= 1_048_576:
        parser.error("--max-bytes must be between 256 and 1048576")
    try:
        if arguments.mode == "text":
            return filter_text(sys.stdin.buffer, arguments.max_bytes)
        return filter_inventory(sys.stdin.buffer, arguments.max_bytes)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"evidence filter rejected input: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
