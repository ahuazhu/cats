#!/usr/bin/env python3
"""Replace only the password in a set of PostgreSQL DSNs.

Used by two callers that must agree exactly: the production deployment, which
composes the control plane's DSNs before Terraform writes them, and the
in-cluster credential refresher, which recomposes them between deployments
(ADR-0029). They were separate copies once; a divergence between them would
show up as a Pod that starts on one path and crash-loops on the other.

    swap-dsn-password.py DSN_JSON SECRET_JSON KEY [KEY ...]

DSN_JSON     a JSON object holding at least the named keys, each a DSN.
SECRET_JSON  the RDS managed master user secret, as stored.

Writes a JSON object of the same keys with the password replaced, to stdout.
Nothing else about a DSN is touched -- scheme, user, host, port, database and
every query parameter survive, because the password is the only part that
rotates and re-deriving the rest would be a new way to be wrong.
"""

import json
import sys
import urllib.parse


def swap_password(dsn, password):
    parts = urllib.parse.urlsplit(dsn)
    if not parts.hostname:
        raise SystemExit("DSN has no host; refusing to rewrite it")
    if not parts.username:
        raise SystemExit("DSN has no user; refusing to rewrite it")
    host = parts.hostname
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
    rotated = {}
    for key in argv[3:]:
        if key not in live:
            raise SystemExit(f"{key} is absent from the source document")
        rotated[key] = swap_password(live[key], password)
    json.dump(rotated, sys.stdout)


if __name__ == "__main__":
    main(sys.argv)
