#!/usr/bin/env python3
"""Replace the password and selected hosts in a set of PostgreSQL DSNs.

Used by two callers that must agree exactly: the production deployment, which
composes the control plane's DSNs before Terraform writes them, and the
in-cluster credential refresher, which recomposes them between deployments
(ADR-0029). They were separate copies once; a divergence between them would
show up as a Pod that starts on one path and crash-loops on the other.

    swap-dsn-password.py DSN_JSON SECRET_JSON [--host KEY=HOST]... KEY [KEY ...]

DSN_JSON     a JSON object holding at least the named keys, each a DSN.
SECRET_JSON  the RDS managed master user secret, as stored.

Writes a JSON object of the same keys with the password replaced, to stdout. A
named host override supports the staged storage-only RDS Proxy cutover; without
one, nothing else about a DSN is touched -- scheme, user, host, port, database
and every query parameter survive.
"""

import json
import re
import sys
import urllib.parse


def validated_hostname(host):
    if host != host.strip() or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise SystemExit(f"invalid host override {host!r}")
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        raise SystemExit(f"invalid host override {host!r}")
    return host


def swap_password(dsn, password, host_override=None):
    parts = urllib.parse.urlsplit(dsn)
    if not parts.hostname:
        raise SystemExit("DSN has no host; refusing to rewrite it")
    if not parts.username:
        raise SystemExit("DSN has no user; refusing to rewrite it")
    host = validated_hostname(host_override) if host_override else parts.hostname
    if ":" in host:
        # Literal IPv6 has to go back inside brackets or the port is lost.
        host = f"[{host}]"
    netloc = "{}:{}@{}".format(
        urllib.parse.quote(parts.username, safe=""),
        urllib.parse.quote(password, safe=""),
        host,
    )
    if parts.port:
        netloc += f":{parts.port}"
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__.strip())
    with open(argv[1], encoding="utf-8") as handle:
        live = json.load(handle)
    with open(argv[2], encoding="utf-8") as handle:
        password = json.load(handle)["password"]
    # An empty password percent-encodes to nothing and yields a syntactically
    # valid, passwordless DSN that deploys cleanly and fails on first connect.
    if not password:
        raise SystemExit("the managed secret holds an empty password")
    host_overrides = {}
    index = 3
    while index < len(argv) and argv[index] == "--host":
        if index + 1 >= len(argv) or "=" not in argv[index + 1]:
            raise SystemExit("--host requires KEY=HOST")
        key, host = argv[index + 1].split("=", 1)
        if not key or key in host_overrides:
            raise SystemExit(f"invalid or duplicate host override key {key!r}")
        host_overrides[key] = validated_hostname(host)
        index += 2
    keys = argv[index:]
    if not keys:
        raise SystemExit(__doc__.strip())
    unknown_overrides = sorted(set(host_overrides) - set(keys))
    if unknown_overrides:
        raise SystemExit(
            f"host override names an unselected key: {unknown_overrides[0]}"
        )

    rotated = {}
    for key in keys:
        if key not in live:
            raise SystemExit(f"{key} is absent from the source document")
        rotated[key] = swap_password(live[key], password, host_overrides.get(key))
    json.dump(rotated, sys.stdout)


if __name__ == "__main__":
    main(sys.argv)
