#!/bin/sh
set -eu

: "${CATS_STRACE_BLOCKD_REAL:?set CATS_STRACE_BLOCKD_REAL}"
: "${CATS_STRACE_BLOCKD_OUTPUT:?set CATS_STRACE_BLOCKD_OUTPUT}"

exec /usr/bin/strace \
    -ff \
    -tt \
    -T \
    -yy \
    -o "$CATS_STRACE_BLOCKD_OUTPUT" \
    -e trace=write,writev,pwrite64,fdatasync,fsync,rename,renameat,renameat2,unlink,unlinkat \
    "$CATS_STRACE_BLOCKD_REAL" "$@"
