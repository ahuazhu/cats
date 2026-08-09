#!/usr/bin/env bash
# Validate the fixed provisioner-owned Node identity filesystem boundary.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

identity_dir=/etc/cats/identity
for ancestor in / /etc /etc/cats; do
  [[ -d $ancestor && ! -L $ancestor ]] || {
    echo "Node identity ancestor is not a real directory: $ancestor" >&2
    exit 1
  }
  ancestor_owner=$(stat -c '%u:%g' "$ancestor")
  ancestor_mode=$(stat -c '%a' "$ancestor")
  [[ $ancestor_owner == 0:0 ]] && (( (8#$ancestor_mode & 022) == 0 )) || {
    echo "Node identity ancestor is not root-owned and protected: $ancestor" >&2
    exit 1
  }
done
[[ -d $identity_dir && ! -L $identity_dir ]] || {
  echo "Node identity directory is not a real directory" >&2
  exit 1
}
[[ $(stat -c '%u:%g:%a' "$identity_dir") == 0:0:700 ]] || {
  echo "Node identity directory must be root:root mode 0700" >&2
  exit 1
}

for identity_file in \
  "$identity_dir/node-identity.v1.json" \
  "$identity_dir/node-registration-key.pem" \
  "$identity_dir/node-registration-credential-id"; do
  [[ -f $identity_file && ! -L $identity_file ]] || {
    echo "provisioner-owned Node identity file is missing or not regular: $identity_file" >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a:%h' "$identity_file") == 0:0:600:1 ]] || {
    echo "Node identity file violates root:root/0600/single-link contract: $identity_file" >&2
    exit 1
  }
done
