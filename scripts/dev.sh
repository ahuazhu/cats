#!/usr/bin/env bash
# One-command local dev stack: control plane + 1 node agent + gateway.
# State lives under /tmp/cats-dev; logs under /tmp/cats-dev/logs.
#
#   scripts/dev.sh up      # build + start everything
#   scripts/dev.sh down    # stop everything and clean children
#   scripts/dev.sh status  # what's running
#
# Then:  cats create dev --root-size 64MiB && cats exec dev -- echo hello
set -euo pipefail

# rustup installs live here; non-login shells may not have sourced the profile.
export PATH="$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE=/tmp/cats-dev
LOGS="$STATE/logs"
API=127.0.0.1:7300
GW=127.0.0.1:7400

up() {
  echo "scripts/dev.sh up is unavailable after the signed Agent-registration cutover." >&2
  echo "Use the process tests for loopback development; production cats-noded requires" >&2
  echo "a provisioner-owned /etc/cats/identity set, the installed shared Guest release," >&2
  echo "and an HTTPS Control origin. No hostname/CLI/shared-token fallback is provided." >&2
  return 1
}

down() {
  # Ask the control plane to stop cats first (best effort), then kill daemons.
  for pidfile in "$STATE"/noded.pid "$STATE"/gatewayd.pid "$STATE"/controld.pid; do
    if [[ -f "$pidfile" ]]; then
      kill "$(cat "$pidfile")" 2>/dev/null || true
      rm -f "$pidfile"
    fi
  done
  # Sweep any leftover per-cat children (blockd / guest-agent).
  pkill -f "$STATE/node-n1" 2>/dev/null || true
  echo "stopped. state kept in $STATE (rm -rf to reset)."
}

status() {
  for name in controld gatewayd noded; do
    if [[ -f "$STATE/$name.pid" ]] && kill -0 "$(cat "$STATE/$name.pid")" 2>/dev/null; then
      echo "$name: running (pid $(cat "$STATE/$name.pid"))"
    else
      echo "$name: stopped"
    fi
  done
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 [up|down|status]" >&2; exit 2 ;;
esac
