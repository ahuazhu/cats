#!/usr/bin/env python3
"""Manage a local chunk cache and its durable remote ChunkStore."""

import argparse
import json
import sys

from chunkstore import ChunkStore, InjectedCrash


def store_from_args(args):
    local = args.local or args.state
    remote = args.remote or args.state
    if not local or not remote:
        raise SystemExit("--state or both --local and --remote are required")
    return ChunkStore(local, remote, args.size, args.chunk_size)


def init(args):
    store = store_from_args(args)
    print(
        f"initialized generation={store.manifest['generation']} "
        f"local={store.local_dir} remote={store.remote_dir}"
    )


def commit(args):
    store = store_from_args(args)
    try:
        result = store.commit(args.crash_at)
    except InjectedCrash as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(86) from error
    print(
        f"commit generation={result.generation} dirty={result.dirty} "
        f"uploaded={result.uploaded} reused={result.reused} "
        f"unmapped={result.unmapped} recovered={str(result.recovered).lower()}"
    )


def clear_cache(args):
    removed = store_from_args(args).clear_cache()
    print(f"cache cleared chunks={removed}")


def report(args):
    result = store_from_args(args).report()
    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return
    for key, value in result.items():
        if key != "backend_stats":
            print(f"{key}={value}")
    if "backend_stats" in result:
        print("backend_stats=" + json.dumps(result["backend_stats"], sort_keys=True))


def verify(args):
    result = store_from_args(args).verify()
    print(
        f"verified generation={result['generation']} "
        f"objects={result['verified_objects']} bytes={result['verified_bytes']}"
    )


def add_geometry(parser):
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--chunk-size", type=int, required=True)


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--state",
        help="backward-compatible combined local and remote directory",
    )
    parser.add_argument("--local", help="NVMe-like cache and dirty-marker directory")
    parser.add_argument("--remote", help="durable ChunkStore directory, e.g. JuiceFS")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    add_geometry(init_parser)
    init_parser.set_defaults(func=init)

    commit_parser = subparsers.add_parser("commit")
    add_geometry(commit_parser)
    commit_parser.add_argument(
        "--crash-at",
        choices=sorted(ChunkStore.CRASH_POINTS),
        help="exit 86 at a durable commit boundary",
    )
    commit_parser.set_defaults(func=commit)

    clear_parser = subparsers.add_parser("clear-cache")
    add_geometry(clear_parser)
    clear_parser.set_defaults(func=clear_cache)

    report_parser = subparsers.add_parser("report")
    add_geometry(report_parser)
    report_parser.add_argument("--json", action="store_true")
    report_parser.set_defaults(func=report)

    verify_parser = subparsers.add_parser("verify")
    add_geometry(verify_parser)
    verify_parser.set_defaults(func=verify)
    return parser


if __name__ == "__main__":
    arguments = build_parser().parse_args()
    arguments.func(arguments)
