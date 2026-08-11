#!/usr/bin/env bash
# Provision the two installation-owned VMM socket namespaces. Per-attempt
# launch code is intentionally unable to create either root.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for required in jq stat systemd-tmpfiles; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "VMM socket namespace provisioning needs $required" >&2
    exit 1
  }
done

identity=/etc/cats/identity/node-identity.v1.json
[[ -f $identity && ! -L $identity ]] || {
  echo "Node identity is missing or not a regular file" >&2
  exit 1
}
state_path_id=$(jq -er '.state_path_id | select(type == "string")' "$identity")
[[ $state_path_id =~ ^[A-Za-z0-9._:-]{1,128}$ ]] \
  && [[ $state_path_id != . && $state_path_id != .. ]] || {
  echo "Node identity state_path_id is not one safe Id component" >&2
  exit 1
}

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

state_directory=/var/lib/cats/node/$state_path_id
[[ -d $state_directory && ! -L $state_directory ]] || {
  echo "identity-selected Node state directory is not provisioned" >&2
  exit 1
}
metadata=$(stat -c '%u:%g:%a' "$state_directory")
owner=${metadata%:*}
mode=${metadata##*:}
[[ $owner == 0:0 ]] && (( (8#$mode & 022) == 0 )) || {
  echo "identity-selected Node state directory is not root-owned and protected" >&2
  exit 1
}

receipt_directory=$state_directory/vmm-socket-receipts
if [[ -e $receipt_directory || -L $receipt_directory ]]; then
  [[ -d $receipt_directory && ! -L $receipt_directory ]] \
    && [[ $(stat -c '%u:%g:%a' "$receipt_directory") == 0:0:700 ]] || {
    echo "VMM socket receipt namespace violates root:root/0700" >&2
    exit 1
  }
else
  mkdir -m 0700 -- "$receipt_directory"
  chown root:root -- "$receipt_directory"
  sync -f "$receipt_directory"
  sync -f "$state_directory"
fi

systemd-tmpfiles --create /usr/lib/tmpfiles.d/cats-vmm.conf
[[ -d /run/cats/vmm-v1 && ! -L /run/cats/vmm-v1 ]] \
  && [[ $(stat -c '%u:%g:%a' /run/cats/vmm-v1) == 0:0:700 ]] || {
  echo "installed VMM socket root violates root:root/0700" >&2
  exit 1
}
