#!/usr/bin/env bash
# Runs on the temporary worker. It never receives source-node credentials or state.
set -euo pipefail

die() { printf 'q124-remote: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }
[[ $EUID -eq 0 ]] || die "must run as root"

imds_token() { curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token; }
imds() { curl -fsS -H "X-aws-ec2-metadata-token: $1" "http://169.254.169.254/latest/$2"; }

prove_identity() {
  need Q124_INSTANCE_ID; need Q124_ACCOUNT_ID; need Q124_REGION
  local token doc
  token=$(imds_token)
  doc=$(imds "$token" dynamic/instance-identity/document)
  jq -e --arg i "$Q124_INSTANCE_ID" --arg a "$Q124_ACCOUNT_ID" --arg r "$Q124_REGION" \
    '.instanceId == $i and .accountId == $a and .region == $r' <<<"$doc" >/dev/null || die "IMDS identity mismatch"
  [[ $(aws sts get-caller-identity --query Account --output text) == "$Q124_ACCOUNT_ID" ]] || die "instance role account mismatch"
}

prove_cache_device() {
  need Q124_CACHE_DEVICE; need Q124_FORMAT_CONFIRMATION; need Q124_INSTANCE_ID
  [[ $Q124_FORMAT_CONFIRMATION == "FORMAT_EPHEMERAL_CACHE_${Q124_INSTANCE_ID}_${Q124_CACHE_DEVICE}" ]] || die "cache format confirmation mismatch"
  [[ -b $Q124_CACHE_DEVICE ]] || die "cache device is not a block device"
  local root parent model
  root=$(findmnt -no SOURCE /)
  parent="/dev/$(lsblk -no PKNAME "$root" | head -1)"
  [[ $Q124_CACHE_DEVICE != "$root" && $Q124_CACHE_DEVICE != "$parent" ]] || die "refusing root disk"
  [[ -z $(lsblk -nrpo MOUNTPOINT "$Q124_CACHE_DEVICE" | sed '/^$/d') ]] || die "cache device or child is mounted"
  model=$(lsblk -dno MODEL "$Q124_CACHE_DEVICE")
  [[ $model == *'Instance Storage'* ]] || die "device is not EC2 NVMe Instance Storage"
}

clean_host() {
  [[ ! -e /etc/cats/worker.env && ! -e /var/lib/cats/node && ! -e /opt/cats/bin/cats-noded ]] || die "host already contains Cats identity/state"
  ! pgrep -f '/opt/cats/bin/(cats-noded|cats-blockd|cloud-hypervisor)' >/dev/null || die "Cats process already running"
}

prepare() {
  for name in Q124_NODE_ID Q124_PRIVATE_IP Q124_CONTROL_URL Q124_REGION Q124_CHUNKSTORE_BUCKET Q124_RUNTIME_SECRET_ARN Q124_DB_SECRET_ARN Q124_DB_NAME Q124_CACHE_DEVICE; do need "$name"; done
  prove_identity
  clean_host
  prove_cache_device
  export CATS_DATA_DEVICE=$Q124_CACHE_DEVICE
  export CATS_GUEST_NETWORK_CIDR=${Q124_GUEST_CIDR:-10.240.0.0/16}
  "${Q124_SOURCE_ROOT:-/opt/cats/q124/source}/deploy/aws/metal/install-worker.sh"
  apt-get install -qy awscli jq postgresql-client

  runtime=$(aws secretsmanager get-secret-value --secret-id "$Q124_RUNTIME_SECRET_ARN" --query SecretString --output text)
  auth=$(jq -er '.CATS_AUTH_TOKEN | select(type == "string" and length > 0)' <<<"$runtime") || die "runtime secret lacks CATS_AUTH_TOKEN"
  db=$(aws secretsmanager get-secret-value --secret-id "$Q124_DB_SECRET_ARN" --query SecretString --output text)
  db_host=$(jq -er '.host' <<<"$db"); db_port=$(jq -er '.port' <<<"$db")
  cgroup=$(systemctl show cats-worker.service -p ControlGroup --value)
  [[ $cgroup == /* ]] || cgroup=/system.slice/cats-worker.service
  umask 077
  {
    printf 'CATS_NODE_ID=%q\n' "$Q124_NODE_ID"
    printf 'CATS_NODE_ADVERTISE_URL=http://%s:7301\n' "$Q124_PRIVATE_IP"
    printf 'CATS_NODE_CPUS=1\nCATS_NODE_MEMORY_MIB=1024\n'
    printf 'CATS_CONTROL_PLANE_URL=%q\nCATS_GATEWAY_URL=%q\n' "$Q124_CONTROL_URL" "$Q124_CONTROL_URL"
    printf 'CATS_AWS_REGION=%q\nCATS_S3_BUCKET=%q\n' "$Q124_REGION" "$Q124_CHUNKSTORE_BUCKET"
    printf 'CATS_POSTGRES_SECRET_ARN=%q\nCATS_POSTGRES_HOST=%q\nCATS_POSTGRES_PORT=%q\n' "$Q124_DB_SECRET_ARN" "$db_host" "$db_port"
    printf 'CATS_POSTGRES_DATABASE=%q\nCATS_POSTGRES_SSLMODE=require\n' "$Q124_DB_NAME"
    printf 'CATS_AUTH_TOKEN=%q\n' "$auth"
    printf 'CATS_GUEST_NETWORK_CIDR=%q\nCATS_METERING_CGROUP_ROOT=/sys/fs/cgroup%s/metering\nRUST_LOG=info\n' "${Q124_GUEST_CIDR:-10.240.0.0/16}" "$cgroup"
  } >/etc/cats/worker.env
  chmod 0600 /etc/cats/worker.env
  install -d -m 0700 /opt/cats/q124
  printf '%s\n' "$Q124_INSTANCE_ID" >/opt/cats/q124/instance-id
  printf '%s\n' "$Q124_NODE_ID" >/opt/cats/q124/node-id
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
  [[ -x /opt/cats/bin/cats-blockd && -x /opt/cats/bin/cloud-hypervisor ]] || die "block/VMM binaries missing"
  lsmod | awk '$1 == "nbd" {found=1} END {exit !found}' || die "nbd module unavailable"
  grep -q 'nbds_max=64' /etc/modprobe.d/cats-nbd.conf || die "NBD option missing"
  systemctl show cats-worker.service -p ExecStart --value | grep -q -- '--vmm ch' || die "Cloud Hypervisor path is not configured"
  aws s3api head-bucket --bucket "$Q124_CHUNKSTORE_BUCKET" >/dev/null
  /opt/cats/bin/render-postgres-url
  psql "$(</run/cats/postgres-url)" -v ON_ERROR_STOP=1 -Atqc 'SELECT 1' | grep -qx 1
  echo validated
}

snapshot() {
  prove_identity
  ledger=${Q124_RUNTIME_LEDGER:-/var/lib/cats/node/runtime-ledger}
  tmp=$(mktemp)
  printf '[]\n' >"$tmp"
  if [[ -d $ledger ]]; then
    while IFS= read -r -d '' record; do
      jq -e '.ledger_version == 1 and (.cat_id | type == "string") and (.blockds | type == "array") and (.volumes | type == "array")' "$record" >/dev/null || die "malformed/unknown runtime ledger record"
      jq -s '.[0] + [.[1]]' "$tmp" "$record" >"$tmp.next" && mv "$tmp.next" "$tmp"
    done < <(find "$ledger" -maxdepth 1 -type f -name '*.json' -print0)
  elif [[ -e $ledger ]]; then
    die "runtime ledger path is not a directory"
  fi
  pending=0
  while IFS= read -r -d '' dir; do
    [[ -r $dir ]] || die "pending-pack directory unreadable"
    count=$(find "$dir" -maxdepth 1 -type f -name '*.pack' -print | wc -l)
    pending=$((pending + count))
  done < <(find /var/lib/cats/node/cats -type d -name pending -print0 2>/dev/null || true)
  result=$(jq -c --argjson pending "$pending" '{cats:([.[].cat_id]|unique),attachments:([.[] | (.blockds[].grant.attachment_id?, .volumes[].attachment_id?) | select(type == "string")]|unique),pending_packs:$pending}' "$tmp")
  rm -f "$tmp"
  printf '%s\n' "$result"
}

assert_idle() {
  prove_identity
  source /etc/cats/worker.env
  "${Q124_SOURCE_ROOT:-/opt/cats/q124/source}/deploy/aws/metal/require-idle-worker.sh" "$CATS_METERING_CGROUP_ROOT"
  snap=$(snapshot)
  jq -e '.cats == [] and .attachments == [] and .pending_packs == 0' <<<"$snap" >/dev/null || die "runtime ledger is not empty"
  [[ ! -d /var/lib/cats/node/runtimes || -z $(find /var/lib/cats/node/runtimes -mindepth 1 -print -quit) ]] || die "runtime directories remain"
  if [[ -n ${Q124_PRIOR_ATTACHMENTS_JSON:-} ]]; then
    jq -e 'type == "array" and all(.[]; type == "string" and test("^att_[A-Za-z0-9_-]+$"))' <<<"$Q124_PRIOR_ATTACHMENTS_JSON" >/dev/null || die "invalid prior attachment set"
    /opt/cats/bin/render-postgres-url
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
  validate) validate ;;
  snapshot) snapshot ;;
  assert-idle) assert_idle ;;
  stop) assert_idle; systemctl disable --now cats-worker cats-postgres-url.timer ;;
  *) die "usage: $0 {prepare|start|validate|snapshot|assert-idle|stop}" ;;
esac
