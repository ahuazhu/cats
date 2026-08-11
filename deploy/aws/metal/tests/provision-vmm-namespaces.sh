#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "SKIP: VMM namespace ownership regression requires root"
  exit 0
fi
command -v jq >/dev/null

script=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/provision-vmm-socket-namespaces.sh
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

new_fixture() {
  local fixture=$1
  mkdir -m 0755 -- "$fixture"
  mkdir -m 0755 -- "$fixture/node"
  printf '%s\n' '{"state_path_id":"node-test"}' >"$fixture/identity.json"
}

assert_exact_tree() {
  local fixture=$1
  [[ $(stat -c '%u:%g:%a' "$fixture/node/node-test") == 0:0:700 ]]
  [[ $(stat -c '%u:%g:%a' "$fixture/node/node-test/vmm-socket-receipts") == 0:0:700 ]]
  [[ $(stat -c '%u:%g:%a' "$fixture/node/node-test/vmm-launch-v1") == 0:0:700 ]]
}

# Fresh install and an exact replay both converge to the same closed roots.
fresh=$temporary/fresh
new_fixture "$fresh"
source "$script"
provision_identity_state_namespaces "$fresh/identity.json" "$fresh/node"
assert_exact_tree "$fresh"
provision_identity_state_namespaces "$fresh/identity.json" "$fresh/node"
assert_exact_tree "$fresh"

# Every mkdir-to-fsync crash window is replay-safe.
for point in \
  after-state-directory-mkdir \
  after-vmm-socket-receipts-mkdir \
  after-vmm-launch-v1-mkdir; do
  crash=$temporary/crash-$point
  new_fixture "$crash"
  if (
    source "$script"
    cats_vmm_namespace_crash_probe() {
      [[ $1 != "$point" ]] || exit 73
    }
    provision_identity_state_namespaces "$crash/identity.json" "$crash/node"
  ); then
    echo "injected namespace crash unexpectedly completed at $point" >&2
    exit 1
  fi
  [[ -d $crash/node/node-test ]]
  source "$script"
  provision_identity_state_namespaces "$crash/identity.json" "$crash/node"
  assert_exact_tree "$crash"
done

# Existing aliases or a widened inode are preserved and rejected.
symlinked=$temporary/symlinked
new_fixture "$symlinked"
mkdir -m 0700 "$symlinked/foreign"
ln -s "$symlinked/foreign" "$symlinked/node/node-test"
if provision_identity_state_namespaces "$symlinked/identity.json" "$symlinked/node"; then
  echo "symlinked state directory was accepted" >&2
  exit 1
fi
[[ -L $symlinked/node/node-test ]]

foreign_file=$temporary/foreign-file
new_fixture "$foreign_file"
printf 'foreign\n' >"$foreign_file/node/node-test"
if provision_identity_state_namespaces "$foreign_file/identity.json" "$foreign_file/node"; then
  echo "foreign state file was accepted" >&2
  exit 1
fi
[[ $(<"$foreign_file/node/node-test") == foreign ]]

widened=$temporary/widened
new_fixture "$widened"
mkdir -m 0755 "$widened/node/node-test"
if provision_identity_state_namespaces "$widened/identity.json" "$widened/node"; then
  echo "widened state directory was accepted" >&2
  exit 1
fi
[[ $(stat -c '%a' "$widened/node/node-test") == 755 ]]

namespace_alias=$temporary/namespace-alias
new_fixture "$namespace_alias"
mkdir -m 0700 "$namespace_alias/node/node-test" "$namespace_alias/foreign"
ln -s "$namespace_alias/foreign" \
  "$namespace_alias/node/node-test/vmm-socket-receipts"
if provision_identity_state_namespaces \
  "$namespace_alias/identity.json" "$namespace_alias/node"; then
  echo "symlinked receipt namespace was accepted" >&2
  exit 1
fi
[[ -L $namespace_alias/node/node-test/vmm-socket-receipts ]]

echo "VMM namespace provisioning regressions passed"
