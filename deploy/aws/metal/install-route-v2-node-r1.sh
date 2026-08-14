#!/bin/sh
# Shared immutable revision-1 Node Route v2 installation transaction.

CATS_ROUTE_V2_NODE_R1_NAMES='public-key-ring.v1.json rotation-operator-trust.v1.json gateway-client-ca-bundle.pem node-machine-server-certificate.pem node-machine-server-private-key.pem'

cats_route_v2_node_r1_compare() (
  candidate=$1
  installed=$2
  for name in $CATS_ROUTE_V2_NODE_R1_NAMES; do
    cmp "$candidate/$name" "$installed/$name" || return 1
  done
)

cats_classify_route_v2_node_r1() (
  validator=$1
  candidate=$2
  installed=$3
  cats_require_worker_deployment_lock || return 1
  "$validator" --directory "$candidate" || return 1
  if [ -e "$installed" ] || [ -L "$installed" ]; then
    "$validator" --directory "$installed" || return 1
    cats_route_v2_node_r1_compare "$candidate" "$installed" || return 1
    printf '%s\n' exact
  else
    printf '%s\n' absent
  fi
)

cats_publish_route_v2_node_r1() (
  set -eu
  validator=$1
  candidate=$2
  installed=$3
  parent=$(dirname "$installed")
  publish=
  cleanup_publish() {
    if [ -n "$publish" ]; then
      rm -rf -- "$publish"
    fi
  }
  trap cleanup_publish EXIT INT TERM

  cats_require_worker_deployment_lock
  "$validator" --directory "$candidate"
  [ ! -e "$installed" ] && [ ! -L "$installed" ]
  if [ ! -e "$parent" ]; then
    install -d -m 0755 "$parent"
  else
    [ -d "$parent" ] && [ ! -L "$parent" ]
  fi
  publish=$(mktemp -d "$parent/.route-v2-r1.XXXXXX")
  chmod 0700 "$publish"
  for name in $CATS_ROUTE_V2_NODE_R1_NAMES; do
    mode=0644
    [ "$name" != node-machine-server-private-key.pem ] || mode=0600
    install -m "$mode" "$candidate/$name" "$publish/$name"
    sync -f "$publish/$name"
  done
  "$validator" --directory "$publish"
  sync -f "$publish"
  [ ! -e "$installed" ] && [ ! -L "$installed" ]
  mv -T -- "$publish" "$installed"
  publish=
  sync -f "$parent"
  "$validator" --directory "$installed"
  cats_route_v2_node_r1_compare "$candidate" "$installed"
)
