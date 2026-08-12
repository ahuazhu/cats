#!/usr/bin/env bash
# Provision the installation-owned VMM state namespace and the fixed runtime
# socket roots. Per-attempt launch code is intentionally unable to create or
# replace any of these roots.
set -euo pipefail

cats_vmm_namespace_crash_probe() { :; }

validate_installed_runtime_socket_root() {
  local directory=$1
  local label=$2

  [[ -d $directory && ! -L $directory ]] \
    && [[ $(stat -c '%u:%g:%a' "$directory") == 0:0:700 ]] || {
    echo "installed $label socket root violates root:root/0700" >&2
    return 1
  }
}

validate_or_absent_installed_runtime_socket_root() {
  local directory=$1
  local label=$2

  if [[ -e $directory || -L $directory ]]; then
    validate_installed_runtime_socket_root "$directory" "$label"
  fi
}

provision_identity_state_namespaces() {
  local identity=$1
  local node_parent=$2
  local state_path_id state_directory metadata owner mode namespace

  [[ -f $identity && ! -L $identity ]] || {
    echo "Node identity is missing or not a regular file" >&2
    return 1
  }
  state_path_id=$(jq -er '.state_path_id | select(type == "string")' "$identity")
  [[ $state_path_id =~ ^[A-Za-z0-9._:-]{1,128}$ ]] \
    && [[ $state_path_id != . && $state_path_id != .. ]] || {
    echo "Node identity state_path_id is not one safe Id component" >&2
    return 1
  }

  # Threat model: the deployment transaction owns this tree exclusively. Its
  # caller has already validated every fixed ancestor as root-owned,
  # non-symlink, and group/world non-writable; this function repeats that
  # predicate on the immediate parent. Under that invariant, a validated
  # single `state_path_id` component plus mkdir(1)'s failing EEXIST behavior
  # provides no-follow/no-replace creation without accepting an attacker ABA.
  [[ -d $node_parent && ! -L $node_parent ]] || {
    echo "Node state parent is not a real directory" >&2
    return 1
  }
  metadata=$(stat -c '%u:%g:%a' "$node_parent")
  owner=${metadata%:*}
  mode=${metadata##*:}
  [[ $owner == 0:0 ]] && (( (8#$mode & 022) == 0 )) || {
    echo "Node state parent is not root-owned and protected" >&2
    return 1
  }

  state_directory=$node_parent/$state_path_id
  if [[ -e $state_directory || -L $state_directory ]]; then
    [[ -d $state_directory && ! -L $state_directory ]] \
      && [[ $(stat -c '%u:%g:%a' "$state_directory") == 0:0:700 ]] || {
      echo "identity-selected Node state directory violates root:root/0700" >&2
      return 1
    }
  else
    # Running as root makes the new inode root-owned at creation; -m closes
    # the mode in the same syscall, before any attempt can observe it.
    mkdir -m 0700 -- "$state_directory"
    cats_vmm_namespace_crash_probe after-state-directory-mkdir
  fi
  sync -f "$state_directory"
  sync -f "$node_parent"

  for namespace in vmm-socket-receipts vmm-launch-v1 blockd-socket-intents-v1; do
    local directory=$state_directory/$namespace
    if [[ -e $directory || -L $directory ]]; then
      [[ -d $directory && ! -L $directory ]] \
        && [[ $(stat -c '%u:%g:%a' "$directory") == 0:0:700 ]] || {
        echo "runtime $namespace namespace violates root:root/0700" >&2
        return 1
      }
    else
      mkdir -m 0700 -- "$directory"
      cats_vmm_namespace_crash_probe "after-$namespace-mkdir"
    fi
    sync -f "$directory"
    sync -f "$state_directory"
  done
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for required in jq stat sync systemd-tmpfiles; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "VMM namespace provisioning needs $required" >&2
    exit 1
  }
done

identity=/etc/cats/identity/node-identity.v1.json
for ancestor in / /var /var/lib /var/lib/cats /var/lib/cats/node; do
  [[ -d $ancestor && ! -L $ancestor ]] || {
    echo "Node state ancestor is not a real directory: $ancestor" >&2
    exit 1
  }
  metadata=$(stat -c '%u:%g:%a' "$ancestor")
  owner=${metadata%:*}
  mode=${metadata##*:}
  [[ $owner == 0:0 ]] && (( (8#$mode & 022) == 0 )) || {
    echo "Node state ancestor is not root-owned and protected: $ancestor" >&2
    exit 1
  }
done

provision_identity_state_namespaces "$identity" /var/lib/cats/node

# Do not let tmpfiles repair or traverse a pre-existing foreign inode. The
# deployment transaction may create an absent installation root, but an
# existing root is authority only when it already has the frozen identity.
validate_or_absent_installed_runtime_socket_root /run/cats/vmm-v1 VMM
validate_or_absent_installed_runtime_socket_root /run/cats/blockd-v1 blockd
systemd-tmpfiles --create /usr/lib/tmpfiles.d/cats-vmm.conf
validate_installed_runtime_socket_root /run/cats/vmm-v1 VMM
validate_installed_runtime_socket_root /run/cats/blockd-v1 blockd
