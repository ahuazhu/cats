#!/usr/bin/env bash
# Dedicated real-Guest regression for the Cats mount-propagation contract.
# Run after install.sh on an isolated metal acceptance stack. This creates and
# destroys only its own disposable Cat; it does not update an existing Cat.
set -euo pipefail

CATS=${CATS:-/opt/cats/bin/cats}
export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
if [[ -z ${CATS_TOKEN:-} ]]; then
  CATS_TOKEN=$(
    sudo sed -n 's/^CATS_ADMIN_TOKEN=//p' /etc/cats/cats.env 2>/dev/null |
      tail -1
  )
  export CATS_TOKEN
fi
[[ -n ${CATS_TOKEN:-} ]] || {
  echo "set CATS_TOKEN (or CATS_ADMIN_TOKEN in /etc/cats/cats.env)" >&2
  exit 1
}

repo=$(cd "$(dirname "$0")/../.." && pwd)
guest_probe=$repo/deploy/metal/guest-mount-propagation-e2e.sh
cat_name=${CAT_NAME:-metal-mount-propagation-e2e}
created=false

cleanup() {
  if [[ $created == true ]]; then
    "$CATS" destroy "$cat_name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"$CATS" destroy "$cat_name" >/dev/null 2>&1 || true
"$CATS" create "$cat_name" \
  --cpus 2 \
  --memory 2GiB \
  --root-size 8GiB \
  --no-auto-suspend \
  --expires-in 21600 \
  ${CATS_CREATE_ARGS:-}
created=true

# The regression oracle needs the real PostgreSQL 17 executable, not a mock
# program or captured findmnt output. policy-rc.d keeps package installation
# from starting a system cluster before the probe creates its chroot clusters.
"$CATS" exec --timeout 900 "$cat_name" -- sh -ceu '
  printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d
  chmod 0755 /usr/sbin/policy-rc.d
  printf "%s\n" \
    "deb http://archive.ubuntu.com/ubuntu noble-updates main universe" \
    "deb http://security.ubuntu.com/ubuntu noble-security main universe" \
    > /etc/apt/sources.list.d/cats-acceptance.sources.list
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg
  install -d -m 0755 /usr/share/postgresql-common/pgdg
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc |
    gpg --dearmor --yes -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg
  printf "%s\n" \
    "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg] https://apt.postgresql.org/pub/repos/apt noble-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    postgresql-17
'

"$CATS" exec \
  --timeout 600 \
  --stdin-file "$guest_probe" \
  "$cat_name" \
  -- bash

"$CATS" destroy "$cat_name"
created=false
