#!/usr/bin/env bash
# Real Cloud Hypervisor + PersistentDisk acceptance run on a deployed Host.
# Uses only the clean-slate synchronous slug protocol. A successful Running
# response is also the physical oracle: noded returns it only after blockd,
# Cloud Hypervisor and the Guest have confirmed the exact ext4 mount ready.
set -uo pipefail

CATS=${CATS:-/opt/cats/bin/cats}
export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
if [[ -z ${CATS_TOKEN:-} ]]; then
  CATS_TOKEN=$(sudo sed -n 's/^CATS_ADMIN_TOKEN=//p' /etc/cats/cats.env 2>/dev/null | tail -1)
  export CATS_TOKEN
fi

die() { echo "metal semantic e2e: $*" >&2; exit 1; }
[[ -x $CATS ]] || die "cats CLI is not executable: $CATS"
command -v jq >/dev/null 2>&1 || die "jq is required"
[[ -n ${CATS_TOKEN:-} ]] || die "set CATS_TOKEN (or CATS_ADMIN_TOKEN in /etc/cats/cats.env)"
[[ ${CATS_BOOT_IMAGE:-} =~ ^sha256:[0-9a-f]{64}$ ]] || \
  die "set CATS_BOOT_IMAGE to the exact sha256 digest of an installed Root image manifest"

suffix=${CATS_E2E_SUFFIX:-$(date +%s)-$$}
CAT=${CATS_E2E_CAT_SLUG:-e2e-cat-$suffix}
DISK=${CATS_E2E_DISK_SLUG:-e2e-disk-$suffix}
MOUNT=${CATS_E2E_MOUNT_PATH:-/data}
[[ $CAT =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "invalid Cat slug: $CAT"
[[ $DISK =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "invalid Disk slug: $DISK"

pass=0
fail=0
CAT_CREATED=0
DISK_CREATED=0

ok() { pass=$((pass + 1)); echo "  PASS  $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }
expect_json() { # description, jq expression, expected, document
  local description=$1 expression=$2 expected=$3 document=$4 actual
  actual=$(jq -er "$expression" <<<"$document" 2>/dev/null) || actual='<invalid-json>'
  if [[ $actual == "$expected" ]]; then
    ok "$description"
  else
    bad "$description (wanted '$expected', got '$actual')"
  fi
}
cats_json() { "$CATS" --json "$@" 2>&1; }
cat_vmm_count() {
  local cat_id=$1 process executable count=0
  for process in /proc/[0-9]*; do
    executable=$(readlink "$process/exe" 2>/dev/null) || continue
    [[ ${executable##*/} == cloud-hypervisor ]] || continue
    if tr '\0' ' ' < "$process/cmdline" 2>/dev/null | grep -Fq -- "$cat_id"; then
      count=$((count + 1))
    fi
  done
  echo "$count"
}
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ $CAT_CREATED -eq 1 ]]; then
    cats_json destroy "$CAT" >/dev/null 2>&1 || true
  fi
  if [[ $DISK_CREATED -eq 1 ]]; then
    cats_json disk destroy "$DISK" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

echo "== 1. PersistentDisk create and semantic replay =="
out=$(cats_json disk create "$DISK" --size 1GiB) || die "disk create failed: $out"
DISK_CREATED=1
DISK_ID=$(jq -er '.disk.disk_id' <<<"$out") || die "disk create returned invalid JSON: $out"
expect_json "disk created" '.code' disk_created "$out"
retry=$(cats_json disk create "$DISK" --size 1GiB) || die "disk create replay failed: $retry"
expect_json "same disk create is already_exists" '.code' already_exists "$retry"
expect_json "same disk create preserves ID" '.disk.disk_id' "$DISK_ID" "$retry"

echo "== 2. Cat create performs real Root/Persistent attach and Guest mount =="
out=$(cats_json create "$CAT" \
  --boot-image "$CATS_BOOT_IMAGE" --cpu 1 --memory 512MiB --mount "$DISK:$MOUNT") \
  || die "Cat create failed: $out"
CAT_CREATED=1
CAT_ID=$(jq -er '.cat.cat_id' <<<"$out") || die "Cat create returned invalid JSON: $out"
FIRST_NODE=$(jq -er '.cat.node_id' <<<"$out") || die "Cat create did not return placement: $out"
expect_json "Cat create reaches Running" '.cat.state' running "$out"
expect_json "Cat create returns cat_created" '.code' cat_created "$out"
expect_json "Cat reports exact PersistentDisk" '.cat.mounts[0].disk_id' "$DISK_ID" "$out"
expect_json "Cat reports exact Guest mount path" '.cat.mounts[0].mount_path' "$MOUNT" "$out"
if [[ $(cat_vmm_count "$CAT_ID") -eq 1 ]]; then
  ok "one Cloud Hypervisor process owns the Running Cat"
else
  bad "expected exactly one Cloud Hypervisor process for $CAT_ID"
fi
retry=$(cats_json create "$CAT" \
  --boot-image "$CATS_BOOT_IMAGE" --cpu 1 --memory 512MiB --mount "$DISK:$MOUNT") \
  || die "Cat create replay failed: $retry"
expect_json "same Cat create is already_exists" '.code' already_exists "$retry"
expect_json "same Cat create preserves ID" '.cat.cat_id' "$CAT_ID" "$retry"
shown=$(cats_json get "$CAT") || die "Cat get failed: $shown"
expect_json "Cat get resolves the current slug" '.cat_id' "$CAT_ID" "$shown"
listed=$(cats_json ls) || die "Cat ls failed: $listed"
expect_json "Cat ls contains the current entity" \
  "[.[] | select(.cat_id == \"$CAT_ID\")] | length" 1 "$listed"
shown=$(cats_json disk get "$DISK") || die "disk get failed: $shown"
expect_json "Disk get resolves the current slug" '.disk_id' "$DISK_ID" "$shown"
listed=$(cats_json disk ls) || die "disk ls failed: $listed"
expect_json "Disk ls contains the current entity" \
  "[.[] | select(.disk_id == \"$DISK_ID\")] | length" 1 "$listed"

echo "== 3. Suspended is Host-bound and Run is idempotent =="
out=$(cats_json suspend "$CAT") || die "suspend failed: $out"
expect_json "suspend reaches Suspended" '.cat.state' suspended "$out"
retry=$(cats_json suspend "$CAT") || die "suspend replay failed: $retry"
expect_json "same suspend is already_suspended" '.code' already_suspended "$retry"
out=$(cats_json run "$CAT") || die "run from Suspended failed: $out"
expect_json "run from Suspended reaches Running" '.cat.state' running "$out"
retry=$(cats_json run "$CAT") || die "run replay failed: $retry"
expect_json "same run is already_running" '.code' already_running "$retry"

echo "== 4. Warm exits CH; Run restores the Host-bound snapshot =="
out=$(cats_json warm "$CAT") || die "warm failed: $out"
expect_json "warm reaches Warm" '.cat.state' warm "$out"
if [[ $(cat_vmm_count "$CAT_ID") -eq 0 ]]; then
  ok "Warm has no Cloud Hypervisor process"
else
  bad "Cloud Hypervisor remains for Warm Cat $CAT_ID"
fi
retry=$(cats_json warm "$CAT") || die "warm replay failed: $retry"
expect_json "same warm is already_warm" '.code' already_warm "$retry"
out=$(cats_json run "$CAT") || die "run from Warm failed: $out"
expect_json "run from Warm reaches Running" '.cat.state' running "$out"

echo "== 5. Cold releases placement; binding changes are semantic and replayable =="
out=$(cats_json cold "$CAT") || die "cold failed: $out"
expect_json "cold reaches Cold" '.cat.state' cold "$out"
expect_json "Cold has no placement" 'if .cat.node_id == null then "null" else .cat.node_id end' null "$out"
retry=$(cats_json cold "$CAT") || die "cold replay failed: $retry"
expect_json "same cold is already_cold" '.code' already_cold "$retry"
out=$(cats_json disk detach "$DISK" --cat "$CAT") || die "disk detach failed: $out"
expect_json "disk detached" '.code' disk_detached "$out"
expect_json "detached disk has no binding" 'if .disk.binding == null then "null" else "bound" end' null "$out"
retry=$(cats_json disk detach "$DISK" --cat "$CAT") || die "disk detach replay failed: $retry"
expect_json "same detach is already_detached" '.code' already_detached "$retry"
out=$(cats_json disk attach "$DISK" --cat "$CAT" --mount "$MOUNT") || die "disk attach failed: $out"
expect_json "disk attached" '.code' disk_attached "$out"
expect_json "binding points to exact Cat" '.disk.binding.cat_id' "$CAT_ID" "$out"
retry=$(cats_json disk attach "$DISK" --cat "$CAT" --mount "$MOUNT") || die "disk attach replay failed: $retry"
expect_json "same attach is already_attached" '.code' already_attached "$retry"

echo "== 6. Cold Run remounts the same ext4 PersistentDisk =="
out=$(cats_json run "$CAT") || die "run from Cold failed: $out"
expect_json "Cold run reaches Running after Guest mount-ready" '.cat.state' running "$out"
SECOND_NODE=$(jq -er '.cat.node_id' <<<"$out") || die "Cold run did not return placement: $out"
echo "  INFO  first_node=$FIRST_NODE cold_run_node=$SECOND_NODE cat_id=$CAT_ID disk_id=$DISK_ID"
if [[ $(cat_vmm_count "$CAT_ID") -eq 1 ]]; then
  ok "Cold Run owns exactly one Cloud Hypervisor process"
else
  bad "expected exactly one Cloud Hypervisor process after Cold Run"
fi

echo "== 7. Destroy releases slugs; reuse creates new immutable IDs =="
out=$(cats_json destroy "$CAT") || die "Cat destroy failed: $out"
CAT_CREATED=0
expect_json "Cat destroy reaches Destroyed" '.cat.state' destroyed "$out"
out=$(cats_json disk destroy "$DISK") || die "disk destroy failed: $out"
DISK_CREATED=0
expect_json "disk destroy reaches Deleted" '.disk.status' deleted "$out"

replacement_disk=$(cats_json disk create "$DISK" --size 1GiB) \
  || die "disk slug reuse failed: $replacement_disk"
DISK_CREATED=1
REPLACEMENT_DISK_ID=$(jq -er '.disk.disk_id' <<<"$replacement_disk") \
  || die "replacement disk response invalid: $replacement_disk"
if [[ $REPLACEMENT_DISK_ID != "$DISK_ID" ]]; then
  ok "Disk slug reuse creates a new immutable ID"
else
  bad "Disk slug reuse retained destroyed ID $DISK_ID"
fi

replacement_cat=$(cats_json create "$CAT" \
  --boot-image "$CATS_BOOT_IMAGE" --cpu 1 --memory 512MiB) \
  || die "Cat slug reuse failed: $replacement_cat"
CAT_CREATED=1
REPLACEMENT_CAT_ID=$(jq -er '.cat.cat_id' <<<"$replacement_cat") \
  || die "replacement Cat response invalid: $replacement_cat"
if [[ $REPLACEMENT_CAT_ID != "$CAT_ID" ]]; then
  ok "Cat slug reuse creates a new immutable ID"
else
  bad "Cat slug reuse retained destroyed ID $CAT_ID"
fi

cats_json destroy "$CAT" >/dev/null || die "replacement Cat cleanup failed"
CAT_CREATED=0
cats_json disk destroy "$DISK" >/dev/null || die "replacement disk cleanup failed"
DISK_CREATED=0
trap - EXIT INT TERM

echo
echo "metal semantic e2e: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
