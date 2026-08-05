#!/usr/bin/env bash
# Runs on the temporary worker. It never receives source-node credentials or state.
set -euo pipefail

die() { printf 'q124-remote: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }
if [[ -n ${Q124_ROOT_PROBE_BIN:-} ]]; then
  "$Q124_ROOT_PROBE_BIN" || die "root probe failed"
else
  [[ $EUID -eq 0 ]] || die "must run as root"
fi

FIND_BIN=${Q124_FIND_BIN:-find}
FINDMNT_BIN=${Q124_FINDMNT_BIN:-findmnt}
STATE_DIR=${Q124_STATE_DIR:-/var/lib/cats/node}
WORKER_ENV=${Q124_WORKER_ENV:-/etc/cats/worker.env}
BIN_ROOT=${Q124_BIN_ROOT:-/opt/cats/bin}

awsq() {
  need Q124_REGION
  aws --region "$Q124_REGION" "$@"
}

imds_token() { curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token; }
imds() { curl -fsS -H "X-aws-ec2-metadata-token: $1" "http://169.254.169.254/latest/$2"; }

prove_identity() {
  need Q124_INSTANCE_ID; need Q124_ACCOUNT_ID; need Q124_REGION
  local token doc
  token=$(imds_token)
  doc=$(imds "$token" dynamic/instance-identity/document)
  jq -e --arg i "$Q124_INSTANCE_ID" --arg a "$Q124_ACCOUNT_ID" --arg r "$Q124_REGION" \
    '.instanceId == $i and .accountId == $a and .region == $r' <<<"$doc" >/dev/null || die "IMDS identity mismatch"
  [[ $(awsq sts get-caller-identity --query Account --output text) == "$Q124_ACCOUNT_ID" ]] || die "instance role account mismatch"
}

prove_cache_device() {
  need Q124_CACHE_DEVICE; need Q124_FORMAT_CONFIRMATION; need Q124_INSTANCE_ID
  "${Q124_DEVICE_PROOF_BIN:-${Q124_SOURCE_ROOT:-/opt/cats/q124/source}/deploy/aws/qualification/q124-device-proof.sh}" >/dev/null
}

clean_host() {
  [[ ! -e $WORKER_ENV && ! -e $STATE_DIR && ! -e $BIN_ROOT/cats-noded ]] || die "host already contains Cats identity/state"
  ! pgrep -f '/opt/cats/bin/(cats-noded|cats-blockd|cloud-hypervisor)' >/dev/null || die "Cats process already running"
}

prepare() {
  for name in Q124_NODE_ID Q124_PRIVATE_IP Q124_CONTROL_URL Q124_REGION Q124_CHUNKSTORE_BUCKET Q124_RUNTIME_SECRET_ARN Q124_DB_SECRET_ARN Q124_DB_NAME Q124_CACHE_DEVICE Q124_AWS_CLI_VERSION Q124_JQ_VERSION; do need "$name"; done
  prove_identity
  clean_host
  prove_cache_device
  export CATS_DATA_DEVICE=$Q124_CACHE_DEVICE
  export CATS_GUEST_NETWORK_CIDR=${Q124_GUEST_CIDR:-10.240.0.0/16}
  "${Q124_INSTALL_WORKER_BIN:-${Q124_SOURCE_ROOT:-/opt/cats/q124/source}/deploy/aws/metal/install-worker.sh}"
  # q124-ssm bootstraps AWS CLI v2 and jq before it can fetch and verify the
  # reviewed archive. Keep the host preparation explicit and install only the
  # remaining runtime client here; Ubuntu 24.04 has no awscli apt candidate.
  command -v aws >/dev/null 2>&1 || die "AWS CLI bootstrap is missing"
  command -v jq >/dev/null 2>&1 || die "jq bootstrap is missing"
  actual_aws=$(aws --version 2>&1 | sed -n 's/^aws-cli\/\([^ ]*\).*/\1/p')
  [[ $actual_aws == "$Q124_AWS_CLI_VERSION" ]] || die "AWS CLI version differs from pinned bootstrap"
  [[ $(jq --version) == "$Q124_JQ_VERSION" ]] || die "jq version differs from pinned bootstrap"
  apt-get install -qy postgresql-client

  runtime=$(awsq secretsmanager get-secret-value --secret-id "$Q124_RUNTIME_SECRET_ARN" --query SecretString --output text)
  auth=$(jq -er '.CATS_AUTH_TOKEN | select(type == "string" and length > 0)' <<<"$runtime") || die "runtime secret lacks CATS_AUTH_TOKEN"
  db=$(awsq secretsmanager get-secret-value --secret-id "$Q124_DB_SECRET_ARN" --query SecretString --output text)
  db_host=$(jq -er '.host' <<<"$db"); db_port=$(jq -er '.port' <<<"$db")
  cgroup=$(systemctl show cats-worker.service -p ControlGroup --value)
  [[ $cgroup == /* ]] || cgroup=/system.slice/cats-worker.service
  umask 077
  {
    printf 'CATS_NODE_ID=%q\n' "$Q124_NODE_ID"
    printf 'CATS_NODE_ADVERTISE_URL=http://%s:7301\n' "$Q124_PRIVATE_IP"
    # The first registration deliberately cannot fit any real Cat. Provision
    # proves 404 -> empty Cordoned before set-capacity raises this to 1024.
    printf 'CATS_NODE_CPUS=1\nCATS_NODE_MEMORY_MIB=1\n'
    printf 'CATS_CONTROL_PLANE_URL=%q\nCATS_GATEWAY_URL=%q\n' "$Q124_CONTROL_URL" "$Q124_CONTROL_URL"
    printf 'CATS_AWS_REGION=%q\nCATS_S3_BUCKET=%q\n' "$Q124_REGION" "$Q124_CHUNKSTORE_BUCKET"
    printf 'AWS_REGION=%q\nAWS_DEFAULT_REGION=%q\n' "$Q124_REGION" "$Q124_REGION"
    printf 'CATS_POSTGRES_SECRET_ARN=%q\nCATS_POSTGRES_HOST=%q\nCATS_POSTGRES_PORT=%q\n' "$Q124_DB_SECRET_ARN" "$db_host" "$db_port"
    printf 'CATS_POSTGRES_DATABASE=%q\nCATS_POSTGRES_SSLMODE=require\n' "$Q124_DB_NAME"
    printf 'CATS_AUTH_TOKEN=%q\n' "$auth"
    printf 'CATS_GUEST_NETWORK_CIDR=%q\nCATS_METERING_CGROUP_ROOT=/sys/fs/cgroup%s/metering\nRUST_LOG=info\n' "${Q124_GUEST_CIDR:-10.240.0.0/16}" "$cgroup"
  } >"$WORKER_ENV"
  chmod 0600 "$WORKER_ENV"
  marker_dir=${Q124_MARKER_DIR:-/opt/cats/q124}
  install -d -m 0700 "$marker_dir"
  printf '%s\n' "$Q124_INSTANCE_ID" >"$marker_dir/instance-id"
  printf '%s\n' "$Q124_NODE_ID" >"$marker_dir/node-id"
  systemctl enable --now cats-postgres-url.timer
  systemctl is-active --quiet cats-postgres-url.timer
  echo prepared
}

validate() {
  prove_identity
  [[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm unavailable"
  systemctl is-active --quiet cats-worker
  systemctl is-active --quiet cats-postgres-url.timer
  curl -fsS http://127.0.0.1:7301/healthz >/dev/null
  [[ -x $BIN_ROOT/cats-blockd && -x $BIN_ROOT/cloud-hypervisor ]] || die "block/VMM binaries missing"
  lsmod | awk '$1 == "nbd" {found=1} END {exit !found}' || die "nbd module unavailable"
  grep -q 'nbds_max=64' /etc/modprobe.d/cats-nbd.conf || die "NBD option missing"
  systemctl show cats-worker.service -p ExecStart --value | grep -q -- '--vmm ch' || die "Cloud Hypervisor path is not configured"
  awsq s3api head-bucket --bucket "$Q124_CHUNKSTORE_BUCKET" >/dev/null
  "$BIN_ROOT/render-postgres-url"
  psql "$(</run/cats/postgres-url)" -v ON_ERROR_STOP=1 -Atqc 'SELECT 1' | grep -qx 1
  echo validated
}

set_capacity() {
  prove_identity
  systemctl is-active --quiet cats-worker || die "worker is not running at staged 1 MiB capacity"
  [[ $(grep -c '^CATS_NODE_MEMORY_MIB=' "$WORKER_ENV") == 1 ]] || die "memory capacity line is not unique"
  [[ $(grep -c '^CATS_NODE_MEMORY_MIB=1$' "$WORKER_ENV") == 1 ]] || die "initial 1 MiB capacity line is not unique"
  sed -i 's/^CATS_NODE_MEMORY_MIB=1$/CATS_NODE_MEMORY_MIB=1024/' "$WORKER_ENV"
  [[ $(grep -c '^CATS_NODE_MEMORY_MIB=1024$' "$WORKER_ENV") == 1 ]] || die "capacity transition failed"
  systemctl restart cats-worker
  systemctl is-active --quiet cats-worker
}

snapshot() {
  prove_identity
  assert_cache_mount
  ledger=${Q124_RUNTIME_LEDGER:-$STATE_DIR/runtime-ledger}
  local tmp records pending_dirs packs
  tmp=$(mktemp)
  records=$(mktemp)
  pending_dirs=$(mktemp)
  packs=$(mktemp)
  cleanup_snapshot() { rm -f "$tmp" "$tmp.next" "$records" "$pending_dirs" "$packs"; }
  trap cleanup_snapshot RETURN
  printf '[]\n' >"$tmp"
  if [[ -d $ledger ]]; then
    "$FIND_BIN" "$ledger" -maxdepth 1 -type f -name '*.json' -print0 >"$records" \
      || die "runtime ledger traversal failed"
    while IFS= read -r -d '' record; do
      jq -e '.ledger_version == 1 and (.cat_id | type == "string") and (.blockds | type == "array") and (.volumes | type == "array")' "$record" >/dev/null || die "malformed/unknown runtime ledger record"
      jq -s '.[0] + [.[1]]' "$tmp" "$record" >"$tmp.next" && mv "$tmp.next" "$tmp"
    done <"$records"
  elif [[ -e $ledger ]]; then
    die "runtime ledger path is not a directory"
  fi
  pending=0
  cats_root=$STATE_DIR/cats
  if [[ -d $cats_root ]]; then
    "$FIND_BIN" "$cats_root" -type d -name pending -print0 >"$pending_dirs" \
      || die "pending-pack directory traversal failed"
    while IFS= read -r -d '' dir; do
      [[ -r $dir ]] || die "pending-pack directory unreadable"
      : >"$packs"
      "$FIND_BIN" "$dir" -maxdepth 1 -type f -name '*.pack' -print0 >"$packs" \
        || die "pending-pack journal traversal failed"
      while IFS= read -r -d '' _pack; do
        pending=$((pending + 1))
      done <"$packs"
    done <"$pending_dirs"
  elif [[ -e $cats_root ]]; then
    die "Cats state path is not a directory"
  fi
  result=$(jq -c --argjson pending "$pending" '{cats:([.[].cat_id]|unique),attachments:([.[] | (.blockds[].grant.attachment_id?, .volumes[].attachment_id?) | select(type == "string")]|unique),pending_packs:$pending}' "$tmp")
  trap - RETURN
  cleanup_snapshot
  printf '%s\n' "$result"
}

assert_cache_mount() {
  need Q124_CACHE_DEVICE
  if [[ -n ${Q124_BLOCK_DEVICE_PROBE_BIN:-} ]]; then
    "$Q124_BLOCK_DEVICE_PROBE_BIN" "$Q124_CACHE_DEVICE" \
      || die "manifest cache device is not a block device"
  else
    [[ -b $Q124_CACHE_DEVICE ]] || die "manifest cache device is not a block device"
  fi
  local mount_source expected_source actual_source mount_table
  mount_table=$(mktemp)
  trap 'rm -f "$mount_table"' RETURN
  "$FINDMNT_BIN" --json --output TARGET,SOURCE >"$mount_table" \
    || die "cache mount table probe failed"
  mount_source=$(jq -er '
    [.filesystems[] | select(.target == "/var/lib/cats")] |
    select(length == 1) | .[0].source | select(type == "string" and length > 0)
  ' "$mount_table") || die "cache mount record is missing or overmounted"
  expected_source=$(readlink -f -- "$Q124_CACHE_DEVICE") || die "cache device resolution failed"
  actual_source=$(readlink -f -- "$mount_source") || die "cache mount source resolution failed"
  [[ -n $expected_source && $actual_source == "$expected_source" ]] \
    || die "cache mount is not backed by the manifest device"
  rm -f "$mount_table"
  trap - RETURN
}

assert_idle() {
  prove_identity
  assert_cache_mount
  source "$WORKER_ENV"
  "${Q124_SOURCE_ROOT:-/opt/cats/q124/source}/deploy/aws/metal/require-idle-worker.sh" "$CATS_METERING_CGROUP_ROOT" "$BIN_ROOT"
  snap=$(snapshot)
  jq -e '.cats == [] and .attachments == [] and .pending_packs == 0' <<<"$snap" >/dev/null || die "runtime ledger is not empty"
  runtimes=$STATE_DIR/runtimes
  if [[ -d $runtimes ]]; then
    runtime_entries=$(mktemp)
    trap 'rm -f "$runtime_entries"' RETURN
    "$FIND_BIN" "$runtimes" -mindepth 1 -print -quit >"$runtime_entries" \
      || die "runtime directory traversal failed"
    [[ ! -s $runtime_entries ]] || die "runtime directories remain"
    rm -f "$runtime_entries"
    trap - RETURN
  elif [[ -e $runtimes ]]; then
    die "runtime path is not a directory"
  fi
  if [[ -n ${Q124_PRIOR_ATTACHMENTS_JSON:-} ]]; then
    jq -e 'type == "array" and all(.[]; type == "string" and test("^att_[A-Za-z0-9_-]+$"))' <<<"$Q124_PRIOR_ATTACHMENTS_JSON" >/dev/null || die "invalid prior attachment set"
    "$BIN_ROOT/render-postgres-url"
    while IFS= read -r attachment; do
      count=$(psql "$(</run/cats/postgres-url)" -v ON_ERROR_STOP=1 -v owner="$attachment" -Atqc "SELECT count(*) FROM cats_storage_volumes WHERE lease_owner = :'owner'")
      [[ $count == 0 ]] || die "old attachment still owns a storage lease"
    done < <(jq -r '.[]' <<<"$Q124_PRIOR_ATTACHMENTS_JSON")
  fi
  echo idle
}

case ${1:-} in
  prepare) prepare ;;
  start) prove_identity; systemctl enable --now cats-worker; systemctl is-active --quiet cats-worker ;;
  set-capacity) set_capacity ;;
  validate) validate ;;
  snapshot) snapshot ;;
  assert-idle) assert_idle ;;
  stop) assert_idle; systemctl disable --now cats-worker cats-postgres-url.timer ;;
  *) die "usage: $0 {prepare|start|set-capacity|validate|snapshot|assert-idle|stop}" ;;
esac
