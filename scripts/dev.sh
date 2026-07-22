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
  mkdir -p "$STATE" "$LOGS" "$STATE/blob"
  echo "building workspace..."
  (cd "$ROOT" && cargo build --workspace -q)
  BIN="$ROOT/target/debug"

  echo "starting control plane on http://$API"
  "$BIN/cats-controld" \
    --listen "$API" \
    --db-path "$STATE/control.db" \
    --metadata-store-adapter sqlite \
    --metadata-store-option "path=$STATE/storage-meta.db" \
    >"$LOGS/controld.log" 2>&1 &
  echo $! > "$STATE/controld.pid"

  echo "starting gateway on http://$GW"
  "$BIN/cats-gatewayd" \
    --listen "$GW" \
    --control-plane-url "http://$API" \
    >"$LOGS/gatewayd.log" 2>&1 &
  echo $! > "$STATE/gatewayd.pid"

  sleep 0.5
  echo "starting node agent n1"
  "$BIN/cats-noded" \
    --node-id n1 \
    --control-plane-url "http://$API" \
    --gateway-url "http://$GW" \
    --state-dir "$STATE/node-n1" \
    --metadata-store-adapter sqlite \
    --metadata-store-option "path=$STATE/storage-meta.db" \
    --object-store-adapter file \
    --object-store-option "root=$STATE/blob" \
    --blockd-bin "$BIN/cats-blockd" \
    --guest-agent-bin "$BIN/cats-guest-agent" \
    >"$LOGS/noded.log" 2>&1 &
  echo $! > "$STATE/noded.pid"

  sleep 0.5
  echo
  echo "ready. try:"
  echo "  cats create dev --root-size 64MiB"
  echo "  cats exec dev -- echo hello"
  echo "  cats suspend dev && cats resume dev"
  echo "  cats expose dev 8080 --name web    # then:"
  echo "  curl -H 'Host: web.dev.default.cats.local' http://$GW/"
  echo
  echo "logs: $LOGS  |  stop: scripts/dev.sh down"
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
