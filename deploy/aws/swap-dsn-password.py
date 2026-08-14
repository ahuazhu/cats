#!/usr/bin/env python3
"""Replace the password and selected hosts in a set of PostgreSQL DSNs.

Used by two callers that must agree exactly: the production deployment, which
composes the control plane's DSNs before Terraform writes them, and the
in-cluster credential refresher, which recomposes them between deployments
(ADR-0029). They were separate copies once; a divergence between them would
show up as a Pod that starts on one path and crash-loops on the other.

    swap-dsn-password.py DSN_JSON SECRET_JSON [--host KEY=HOST]...
      [--schema KEY=SCHEMA]... KEY [KEY ...]

DSN_JSON     a JSON object holding at least the named keys, each a DSN.
SECRET_JSON  the RDS managed master user secret, as stored.

Writes a JSON object of the same keys with the password replaced, to stdout. A
named host override supports the staged storage-only RDS Proxy cutover. A named
schema override replaces every existing `options` query item with exactly one
URL-encoded `-csearch_path=<schema>` item. Without an override, that component
survives byte-for-byte.
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


def validated_schema(schema):
    if not re.fullmatch(r"cats_[a-z0-9_]+", schema) or len(schema) > 63:
        raise SystemExit(f"invalid fresh control schema {schema!r}")
    return schema


def bind_schema(query, schema):
    retained = []
    if query:
        for parameter in query.split("&"):
            raw_key = parameter.partition("=")[0]
            try:
                key = urllib.parse.unquote_plus(raw_key, errors="strict")
            except UnicodeDecodeError as error:
                raise SystemExit("DSN query contains invalid UTF-8") from error
            if key != "options":
                retained.append(parameter)
    retained.append(
        "options=-csearch_path%3D" + urllib.parse.quote(schema, safe="")
    )
    return "&".join(retained)


def swap_password(dsn, password, host_override=None, schema_override=None):
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
    query = parts.query
    if schema_override is not None:
        query = bind_schema(query, validated_schema(schema_override))
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


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
    schema_overrides = {}
    index = 3
    while index < len(argv) and argv[index] in ("--host", "--schema"):
        option = argv[index]
        if index + 1 >= len(argv) or "=" not in argv[index + 1]:
            raise SystemExit(f"{option} requires KEY=VALUE")
        key, value = argv[index + 1].split("=", 1)
        overrides = host_overrides if option == "--host" else schema_overrides
        if not key or key in overrides:
            raise SystemExit(f"invalid or duplicate {option} override key {key!r}")
        overrides[key] = (
            validated_hostname(value)
            if option == "--host"
            else validated_schema(value)
        )
        index += 2
    keys = argv[index:]
    if not keys:
        raise SystemExit(__doc__.strip())
    unknown_overrides = sorted((set(host_overrides) | set(schema_overrides)) - set(keys))
    if unknown_overrides:
        raise SystemExit(
            f"host override names an unselected key: {unknown_overrides[0]}"
        )

    rotated = {}
    for key in keys:
        if key not in live:
            raise SystemExit(f"{key} is absent from the source document")
        rotated[key] = swap_password(
            live[key],
            password,
            host_overrides.get(key),
            schema_overrides.get(key),
        )
    json.dump(rotated, sys.stdout)


if __name__ == "__main__":
    main(sys.argv)
