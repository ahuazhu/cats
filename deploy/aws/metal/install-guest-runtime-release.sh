#!/usr/bin/env bash
# Verify and atomically install the one closed Guest runtime release payload.
set -euo pipefail

mode=${1:-}
argument_1=${2:-}
argument_2=${3:-}
argument_3=${4:-}
node_service=${CATS_NODE_SERVICE_NAME:-cats-worker}
deployment_watchdog_service=cats-worker-deployment-watchdog.service
cats_root=/opt/cats
required_uid=0
required_gid=0
deployment_lock_path=/run/lock/cats/worker-deployment.lock

# Production deliberately has no crash-injection environment variable. Linux
# regression tests replace this no-op in a private copy and kill the process
# at each labeled durability boundary.
crash_probe() { :; }
[[ $mode == verify || $mode == prepare || $mode == commit \
    || $mode == authorize-start || $mode == bind-start \
    || $mode == watchdog-check || $mode == rollback || $mode == recover \
    || $mode == startup-recover ]] || {
  echo "usage: $0 verify|prepare <guest-runtime-release.v1> | authorize-start <token> <owner-pid> <owner-start> | bind-start|commit <token> <main-pid> <main-start> | watchdog-check <token> <owner-pid> <owner-start> | rollback|recover|startup-recover" >&2
  exit 2
}
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

require_deployment_lock() {
  local descriptor=${CATS_WORKER_DEPLOYMENT_LOCK_FD:-} lock_identity fd_identity metadata
  [[ $descriptor =~ ^[0-9]+$ ]] || {
    echo "mutating Guest release commands require the Host deployment lock descriptor" >&2
    return 1
  }
  [[ -e /proc/self/fd/$descriptor ]] || return 1
  lock_identity=$(stat -Lc '%d:%i' "$deployment_lock_path") || return 1
  fd_identity=$(stat -Lc '%d:%i' "/proc/self/fd/$descriptor") || return 1
  test "$lock_identity" = "$fd_identity" || return 1
  metadata=$(stat -Lc '%u:%g:%a:%h' "$deployment_lock_path") || return 1
  test "$metadata" = "$required_uid:$required_gid:600:1" || return 1
  # Acquiring on the inherited open-file description either proves the outer
  # deployment already holds the lock or makes that lock persist in the outer
  # shell after this child exits. A separate deployment cannot overlap it.
  flock -n "$descriptor" || return 1
}

systemd_property() {
  local property=$1 value
  value=$(systemctl show "$node_service" "--property=$property" --value) || {
    echo "cannot query $node_service $property" >&2
    return 1
  }
  [[ -n $value ]] || {
    echo "$node_service returned an empty $property" >&2
    return 1
  }
  printf '%s\n' "$value"
}

require_service_stopped() {
  local load_state active_state
  load_state=$(systemd_property LoadState) || return 1
  active_state=$(systemd_property ActiveState) || return 1
  case "$load_state:$active_state" in
    loaded:inactive|loaded:failed|not-found:inactive|masked:inactive|masked:failed) return 0 ;;
  esac
  echo "$node_service is not provably stopped ($load_state/$active_state)" >&2
  return 1
}

valid_decimal() {
  [[ $1 =~ ^[1-9][0-9]*$ ]]
}

valid_candidate_token() {
  [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

process_start_ticks() {
  local pid=$1 stat_line suffix
  valid_decimal "$pid" || return 1
  [[ -r /proc/$pid/stat ]] || return 1
  IFS= read -r stat_line < "/proc/$pid/stat" || return 1
  suffix=${stat_line##*) }
  set -- $suffix
  [[ $# -ge 20 ]] || return 1
  valid_decimal "${20}" || return 1
  printf '%s\n' "${20}"
}

require_process_identity() {
  local pid=$1 expected_start=$2 actual_start
  actual_start=$(process_start_ticks "$pid") || return 1
  [[ $actual_start == "$expected_start" ]] || {
    echo "process $pid no longer has expected start identity" >&2
    return 1
  }
}

current_main_identity() {
  local main_pid main_start
  main_pid=$(systemd_property MainPID) || return 1
  valid_decimal "$main_pid" || {
    echo "$node_service returned an invalid MainPID" >&2
    return 1
  }
  main_start=$(process_start_ticks "$main_pid") || return 1
  printf '%s:%s\n' "$main_pid" "$main_start"
}

require_service_active() {
  local load_state active_state
  load_state=$(systemd_property LoadState) || return 1
  active_state=$(systemd_property ActiveState) || return 1
  [[ $load_state:$active_state == loaded:active ]] || {
    echo "$node_service is not active ($load_state/$active_state)" >&2
    return 1
  }
}

verify_release() {
  local root=$1
  python3 - "$root" "$required_uid" "$required_gid" <<'PY'
import hashlib, json, os, stat, sys

root = os.path.abspath(sys.argv[1])
required_uid = int(sys.argv[2])
required_gid = int(sys.argv[3])
root_metadata = os.lstat(root)
if (not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != required_uid or root_metadata.st_gid != required_gid):
    raise SystemExit("release root is not a real directory")
manifest_path = os.path.join(root, "manifest.v1.json")
with open(manifest_path, "rb", buffering=0) as source:
    manifest_bytes = source.read(4097)
if not 0 < len(manifest_bytes) <= 4096:
    raise SystemExit("manifest size is outside 1..4096")
manifest = json.loads(manifest_bytes)
canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
if canonical != manifest_bytes:
    raise SystemExit("manifest is not canonical JSON")
if (not isinstance(manifest, dict)
        or set(manifest) != {"version", "guest_runtime_profile", "kernel", "initramfs"}
        or type(manifest["version"]) is not int or manifest["version"] != 1
        or not isinstance(manifest["guest_runtime_profile"], dict)
        or not isinstance(manifest["kernel"], dict)
        or (manifest["initramfs"] is not None and not isinstance(manifest["initramfs"], dict))):
    raise SystemExit("manifest shape/version is invalid")

members = {
    "guest_runtime_profile": ("guest-runtime-profile.v1.json", 4096),
    "kernel": ("guest/vmlinuz", 536870912),
}
if manifest["initramfs"] is not None:
    members["initramfs"] = ("guest/initramfs.img", 536870912)
expected = {"manifest.v1.json"} | {path for path, _ in members.values()}
actual = set()
actual_directories = set()
for directory, names, filenames in os.walk(root, followlinks=False):
    for name in names + filenames:
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, root)
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(f"release contains symlink {relative}")
        if name in names:
            if not stat.S_ISDIR(metadata.st_mode):
                raise SystemExit(f"release contains non-directory entry {relative}")
            actual_directories.add(relative)
        if name in filenames:
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != required_uid or metadata.st_gid != required_gid
                    or stat.S_IMODE(metadata.st_mode) != 0o644):
                raise SystemExit(f"release member is not a single-link regular file: {relative}")
            actual.add(relative)
if actual != expected:
    raise SystemExit(f"release file set mismatch: {sorted(actual ^ expected)}")
if actual_directories != {"guest"}:
    raise SystemExit(f"release directory set mismatch: {sorted(actual_directories)}")

for key, (relative, cap) in members.items():
    entry = manifest[key]
    if (set(entry) != {"path", "sha256", "size_bytes"}
            or not isinstance(entry["path"], str) or entry["path"] != relative
            or not isinstance(entry["sha256"], str)
            or type(entry["size_bytes"]) is not int):
        raise SystemExit(f"manifest entry {key} is invalid")
    path = os.path.join(root, relative)
    metadata = os.lstat(path)
    if not 0 < metadata.st_size <= cap or entry["size_bytes"] != metadata.st_size:
        raise SystemExit(f"release member size mismatch: {relative}")
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    if entry["sha256"] != "sha256:" + digest.hexdigest():
        raise SystemExit(f"release member digest mismatch: {relative}")

with open(os.path.join(root, "guest-runtime-profile.v1.json"), "rb", buffering=0) as source:
    receipt_bytes = source.read(4097)
receipt = json.loads(receipt_bytes)
if json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() != receipt_bytes:
    raise SystemExit("receipt is not canonical JSON")
if (not isinstance(receipt, dict)
        or set(receipt) != {"version", "kernel_digest", "initramfs_digest", "kernel_cmdline", "guest_agent_protocol_version"}):
    raise SystemExit("receipt shape is invalid")
if (type(receipt["version"]) is not int or receipt["version"] != 1
        or type(receipt["guest_agent_protocol_version"]) is not int
        or receipt["guest_agent_protocol_version"] != 1
        or not isinstance(receipt["kernel_digest"], str)
        or not isinstance(receipt["kernel_cmdline"], str)
        or not receipt["kernel_cmdline"]
        or any(ord(character) < 0x20 or ord(character) > 0x7e for character in receipt["kernel_cmdline"])
        or (receipt["initramfs_digest"] is not None
            and not isinstance(receipt["initramfs_digest"], str))):
    raise SystemExit("receipt version is invalid")
if receipt["kernel_digest"] != manifest["kernel"]["sha256"]:
    raise SystemExit("receipt kernel digest does not match manifest")
expected_initramfs = None if manifest["initramfs"] is None else manifest["initramfs"]["sha256"]
if receipt["initramfs_digest"] != expected_initramfs:
    raise SystemExit("receipt initramfs digest does not match manifest")

release_digest = hashlib.sha256(b"cats.release.guest-runtime-manifest.v1\0" + manifest_bytes)
print("sha256:" + release_digest.hexdigest())
PY
}

release_id=""
if [[ $mode == verify || $mode == prepare ]]; then
  source_root=$argument_1
  [[ -n $source_root ]] || { echo "$mode requires a release source" >&2; exit 2; }
  release_id=$(verify_release "$source_root")
fi
[[ $mode == verify ]] && { printf '%s\n' "$release_id"; exit 0; }
if [[ $mode != startup-recover && $mode != watchdog-check ]]; then
  require_deployment_lock
fi
case "$mode" in
  prepare|authorize-start|rollback|recover) require_service_stopped ;;
  bind-start|commit) require_service_active ;;
esac

releases_root="$cats_root/releases"
sets_root="$releases_root/sets"
activation_path="$releases_root/activation.v1"
start_authorization_path="$releases_root/start-authorized.v1"
active_release_root="$cats_root/release"
active_guest_root="$cats_root/guest"
install -d -o "$required_uid" -g "$required_gid" -m 0700 "$sets_root" "$releases_root"
sync -f "$sets_root"
crash_probe "layout-directory-fsync:sets"
sync -f "$releases_root"
crash_probe "layout-directory-fsync:releases"
sync -f "$cats_root"
crash_probe "layout-parent-fsync:cats-root"

valid_release_id() {
  [[ $1 =~ ^sha256:[0-9a-f]{64}$ ]]
}

sync_release_tree() {
  local tree=$1 relative
  while IFS= read -r relative; do
    sync -f "$tree/$relative" || return 1
    crash_probe "set-file-fsync:$relative" || return 1
  done < <(find "$tree" -type f -printf '%P\n' | LC_ALL=C sort)
  sync -f "$tree/guest" || return 1
  crash_probe "set-directory-fsync:guest" || return 1
  sync -f "$tree" || return 1
  crash_probe "set-directory-fsync:root" || return 1
}

copy_source_tree() {
  local source=$1 destination=$2 relative
  rm -rf -- "$destination" || return 1
  install -d -o "$required_uid" -g "$required_gid" -m 0700 "$destination/guest" || return 1
  for relative in manifest.v1.json guest-runtime-profile.v1.json guest/vmlinuz; do
    install -o "$required_uid" -g "$required_gid" -m 0644 \
      "$source/$relative" "$destination/$relative" || return 1
    crash_probe "set-copy:$relative" || return 1
  done
  if [[ -f $source/guest/initramfs.img ]]; then
    install -o "$required_uid" -g "$required_gid" -m 0644 \
      "$source/guest/initramfs.img" "$destination/guest/initramfs.img" || return 1
    crash_probe "set-copy:guest/initramfs.img" || return 1
  fi
  sync_release_tree "$destination" || return 1
}

complete_set() {
  local incomplete=$1 expected_id=$2 target_set
  target_set="$sets_root/$expected_id"
  test "$(verify_release "$incomplete")" = "$expected_id" || return 1
  if [[ -e $target_set || -L $target_set ]]; then
    test "$(verify_release "$target_set")" = "$expected_id" || return 1
    rm -rf -- "$incomplete" || return 1
  else
    mv -T -- "$incomplete" "$target_set" || return 1
    crash_probe "set-marker-rename:$expected_id" || return 1
  fi
  # Sync even on exact replay: a process may have died after rename but before
  # the parent-directory durability boundary.
  sync -f "$sets_root" || return 1
  crash_probe "set-marker-parent-fsync:$expected_id" || return 1
  printf '%s\n' "$target_set"
}

persist_source_set() {
  local source=$1 expected_id=$2 role=$3 incomplete
  incomplete="$releases_root/.$role.incomplete"
  copy_source_tree "$source" "$incomplete" || return 1
  complete_set "$incomplete" "$expected_id" || return 1
}

materialize_active() {
  local destination=$1
  rm -rf -- "$destination" || return 1
  install -d -o "$required_uid" -g "$required_gid" -m 0700 "$destination/guest" || return 1
  install -o "$required_uid" -g "$required_gid" -m 0644 \
    "$active_release_root/guest-runtime-release-manifest.v1.json" \
    "$destination/manifest.v1.json" || return 1
  install -o "$required_uid" -g "$required_gid" -m 0644 \
    "$active_release_root/guest-runtime-profile.v1.json" \
    "$destination/guest-runtime-profile.v1.json" || return 1
  install -o "$required_uid" -g "$required_gid" -m 0644 \
    "$active_guest_root/vmlinuz" "$destination/guest/vmlinuz" || return 1
  if [[ -e $active_guest_root/initramfs.img || -L $active_guest_root/initramfs.img ]]; then
    install -o "$required_uid" -g "$required_gid" -m 0644 \
      "$active_guest_root/initramfs.img" "$destination/guest/initramfs.img" || return 1
  fi
}

verify_active() {
  local expected_id=$1 verification="$releases_root/.active-verification"
  rm -rf -- "$verification" || return 1
  materialize_active "$verification" || return 1
  test "$(verify_release "$verification")" = "$expected_id" || return 1
  rm -rf -- "$verification" || return 1
  sync -f "$releases_root" || return 1
}

persist_active_set() {
  local incomplete="$releases_root/.previous.incomplete" previous_id
  materialize_active "$incomplete" || return 1
  previous_id=$(verify_release "$incomplete") || return 1
  sync_release_tree "$incomplete" || return 1
  complete_set "$incomplete" "$previous_id" >/dev/null || return 1
  printf '%s\n' "$previous_id"
}

install_active_member() {
  local source=$1 active=$2 label=$3 temp
  temp="${active}.incoming"
  rm -f -- "$temp"
  install -o "$required_uid" -g "$required_gid" -m 0644 "$source" "$temp" || return 1
  crash_probe "active-copy:$label" || return 1
  sync -f "$temp" || return 1
  crash_probe "active-temp-fsync:$label" || return 1
  mv -fT -- "$temp" "$active" || return 1
  crash_probe "active-rename:$label" || return 1
  sync -f "$active" || return 1
  crash_probe "active-file-fsync:$label" || return 1
  sync -f "$(dirname "$active")" || return 1
  crash_probe "active-parent-fsync:$label" || return 1
}

install_set() {
  local set=$1
  install -d -o "$required_uid" -g "$required_gid" -m 0755 \
    "$active_release_root" "$active_guest_root" || return 1
  sync -f "$active_release_root" || return 1
  crash_probe "active-layout-directory-fsync:release" || return 1
  sync -f "$active_guest_root" || return 1
  crash_probe "active-layout-directory-fsync:guest" || return 1
  sync -f "$cats_root" || return 1
  crash_probe "active-layout-parent-fsync:cats-root" || return 1
  install_active_member "$set/guest-runtime-profile.v1.json" \
    "$active_release_root/guest-runtime-profile.v1.json" receipt || return 1
  install_active_member "$set/guest/vmlinuz" "$active_guest_root/vmlinuz" kernel || return 1
  if [[ -f $set/guest/initramfs.img ]]; then
    install_active_member "$set/guest/initramfs.img" \
      "$active_guest_root/initramfs.img" initramfs || return 1
  else
    rm -f -- "$active_guest_root/initramfs.img" || return 1
    crash_probe "active-remove:initramfs" || return 1
    sync -f "$active_guest_root" || return 1
    crash_probe "active-parent-fsync:initramfs-absent" || return 1
  fi
  # Manifest is the active local completion marker and is always renamed last.
  install_active_member "$set/manifest.v1.json" \
    "$active_release_root/guest-runtime-release-manifest.v1.json" manifest || return 1
}

write_activation() {
  local incoming_id=$1 previous_id=$2 temp="$activation_path.incoming"
  valid_release_id "$incoming_id" || return 1
  [[ $previous_id == none ]] || valid_release_id "$previous_id" || return 1
  clear_start_authorization || return 1
  rm -f -- "$temp" || return 1
  (umask 077; printf 'version=1\nincoming=%s\nprevious=%s\n' \
    "$incoming_id" "$previous_id" > "$temp") || return 1
  chown "$required_uid:$required_gid" "$temp" || return 1
  chmod 0600 "$temp" || return 1
  sync -f "$temp" || return 1
  crash_probe "activation-file-fsync" || return 1
  # Replacing the retained journal is the retry linearization point. This
  # named pre-replace boundary proves that a crash after recovery and complete
  # candidate persistence still leaves the old recovery authority intact.
  crash_probe "activation-before-journal-replace" || return 1
  mv -fT -- "$temp" "$activation_path" || return 1
  crash_probe "activation-rename" || return 1
  sync -f "$releases_root" || return 1
  crash_probe "activation-parent-fsync" || return 1
}

load_activation() {
  local metadata
  [[ -f $activation_path && ! -L $activation_path ]] || return 1
  metadata=$(stat -c '%u:%g:%a:%h:%F' "$activation_path") || return 1
  test "$metadata" = "$required_uid:$required_gid:600:1:regular file" || return 1
  mapfile -t activation_lines < "$activation_path" || return 1
  [[ ${#activation_lines[@]} -eq 3 && ${activation_lines[0]} == version=1 ]] || return 1
  activation_incoming=${activation_lines[1]#incoming=}
  activation_previous=${activation_lines[2]#previous=}
  [[ ${activation_lines[1]} == "incoming=$activation_incoming" \
      && ${activation_lines[2]} == "previous=$activation_previous" ]] || return 1
  valid_release_id "$activation_incoming" || return 1
  [[ $activation_previous == none ]] || valid_release_id "$activation_previous" || return 1
  test "$(verify_release "$sets_root/$activation_incoming")" = "$activation_incoming" || return 1
  if [[ $activation_previous != none ]]; then
    test "$(verify_release "$sets_root/$activation_previous")" = "$activation_previous" || return 1
  fi
}

write_start_authorization() {
  local incoming_id=$1 token=$2 owner_pid=$3 owner_start=$4 gate=$5 main_pid=$6 main_start=$7
  local temp="$start_authorization_path.incoming"
  valid_release_id "$incoming_id" || return 1
  valid_candidate_token "$token" || return 1
  valid_decimal "$owner_pid" || return 1
  valid_decimal "$owner_start" || return 1
  [[ $gate == armed || $gate == consumed ]] || return 1
  if [[ $main_pid == none || $main_start == none ]]; then
    [[ $main_pid == none && $main_start == none ]] || return 1
  else
    valid_decimal "$main_pid" || return 1
    valid_decimal "$main_start" || return 1
  fi
  rm -f -- "$temp" || return 1
  (umask 077; printf 'version=2\nincoming=%s\ntoken=%s\nowner_pid=%s\nowner_start=%s\ngate=%s\nmain_pid=%s\nmain_start=%s\n' \
    "$incoming_id" "$token" "$owner_pid" "$owner_start" "$gate" \
    "$main_pid" "$main_start" > "$temp") || return 1
  chown "$required_uid:$required_gid" "$temp" || return 1
  chmod 0600 "$temp" || return 1
  sync -f "$temp" || return 1
  crash_probe "start-authorization-file-fsync" || return 1
  mv -fT -- "$temp" "$start_authorization_path" || return 1
  crash_probe "start-authorization-rename" || return 1
  sync -f "$releases_root" || return 1
  crash_probe "start-authorization-parent-fsync" || return 1
}

load_start_authorization() {
  local expected_id=$1 metadata
  [[ -f $start_authorization_path && ! -L $start_authorization_path ]] || return 1
  metadata=$(stat -c '%u:%g:%a:%h:%F' "$start_authorization_path") || return 1
  test "$metadata" = "$required_uid:$required_gid:600:1:regular file" || return 1
  mapfile -t start_authorization_lines < "$start_authorization_path" || return 1
  [[ ${#start_authorization_lines[@]} -eq 8 \
      && ${start_authorization_lines[0]} == version=2 \
      && ${start_authorization_lines[1]} == "incoming=$expected_id" ]] || return 1
  start_authorization_token=${start_authorization_lines[2]#token=}
  start_authorization_owner_pid=${start_authorization_lines[3]#owner_pid=}
  start_authorization_owner_start=${start_authorization_lines[4]#owner_start=}
  start_authorization_gate=${start_authorization_lines[5]#gate=}
  start_authorization_main_pid=${start_authorization_lines[6]#main_pid=}
  start_authorization_main_start=${start_authorization_lines[7]#main_start=}
  [[ ${start_authorization_lines[2]} == "token=$start_authorization_token" \
      && ${start_authorization_lines[3]} == "owner_pid=$start_authorization_owner_pid" \
      && ${start_authorization_lines[4]} == "owner_start=$start_authorization_owner_start" \
      && ${start_authorization_lines[5]} == "gate=$start_authorization_gate" \
      && ${start_authorization_lines[6]} == "main_pid=$start_authorization_main_pid" \
      && ${start_authorization_lines[7]} == "main_start=$start_authorization_main_start" ]] || return 1
  valid_candidate_token "$start_authorization_token" || return 1
  valid_decimal "$start_authorization_owner_pid" || return 1
  valid_decimal "$start_authorization_owner_start" || return 1
  [[ $start_authorization_gate == armed || $start_authorization_gate == consumed ]] || return 1
  if [[ $start_authorization_main_pid == none || $start_authorization_main_start == none ]]; then
    [[ $start_authorization_main_pid == none \
        && $start_authorization_main_start == none ]] || return 1
  else
    valid_decimal "$start_authorization_main_pid" || return 1
    valid_decimal "$start_authorization_main_start" || return 1
  fi
}

clear_start_authorization() {
  if [[ -e $start_authorization_path || -L $start_authorization_path ]]; then
    rm -f -- "$start_authorization_path" || return 1
    crash_probe "start-authorization-remove" || return 1
    sync -f "$releases_root" || return 1
    crash_probe "start-authorization-remove-parent-fsync" || return 1
  fi
}

clear_activation() {
  rm -f -- "$activation_path" || return 1
  crash_probe "activation-remove" || return 1
  sync -f "$releases_root" || return 1
  crash_probe "activation-remove-parent-fsync" || return 1
}

finish_incoming_activation() {
  load_activation || return 1
  install_set "$sets_root/$activation_incoming" || return 1
  verify_active "$activation_incoming" || return 1
}

rollback_activation() {
  if [[ ! -e $activation_path && ! -L $activation_path ]]; then
    return 0
  fi
  load_activation || return 1
  clear_start_authorization || return 1
  if [[ $activation_previous == none ]]; then
    finish_incoming_activation || return 1
    echo "initial Guest release has no rollback set; activation remains uncommitted" >&2
    return 1
  fi
  install_set "$sets_root/$activation_previous" || return 1
  verify_active "$activation_previous" || return 1
}

recover_activation() {
  if [[ ! -e $activation_path && ! -L $activation_path ]]; then
    return 0
  fi
  load_activation || return 1
  if [[ $activation_previous == none ]]; then
    # A first install has no honest rollback target. Finish its exact incoming
    # bytes but retain the journal and keep the Node stopped until the outer
    # deployment repeats readiness and explicitly commits.
    finish_incoming_activation || return 1
    return 0
  fi
  rollback_activation
}

startup_recover() {
  [[ -e $activation_path || -L $activation_path ]] || return 0
  install -d -o "$required_uid" -g "$required_gid" -m 0700 "$(dirname "$deployment_lock_path")"
  if [[ ! -e $deployment_lock_path && ! -L $deployment_lock_path ]]; then
    (umask 077; set -o noclobber; : > "$deployment_lock_path") 2>/dev/null || true
  fi
  [[ -f $deployment_lock_path && ! -L $deployment_lock_path ]] || return 1
  test "$(stat -Lc '%u:%g:%a:%h' "$deployment_lock_path")" = \
    "$required_uid:$required_gid:600:1" || return 1
  exec 8>>"$deployment_lock_path"
  if flock -n 8; then
    export CATS_WORKER_DEPLOYMENT_LOCK_FD=8
    recover_activation || return 1
    # Recovery always retains the journal, even after restoring a previous
    # release. Outer worker artifacts may be only partially replaced, so a
    # standalone service restart remains blocked until the whole deployment
    # transaction replays and commits.
    [[ ! -e $activation_path && ! -L $activation_path ]]
  else
    # A live outer deployment owns the lock and is intentionally starting the
    # candidate for its registration/readiness proof. The authorization is
    # bound to both that process lifetime and an independently supervised
    # watchdog. Consume the one-shot start gate before returning so Restart=
    # always cannot start a second MainPID under the same authorization.
    load_activation || return 1
    load_start_authorization "$activation_incoming" || return 1
    require_process_identity "$start_authorization_owner_pid" \
      "$start_authorization_owner_start" || return 1
    systemctl is-active --quiet "$deployment_watchdog_service" || return 1
    [[ $start_authorization_gate == armed \
        && $start_authorization_main_pid == none \
        && $start_authorization_main_start == none ]] || return 1
    verify_active "$activation_incoming" || return 1
    write_start_authorization "$activation_incoming" \
      "$start_authorization_token" "$start_authorization_owner_pid" \
      "$start_authorization_owner_start" consumed none none
  fi
}

case "$mode" in
  prepare)
    recover_activation
    recovered_previous_id=""
    if [[ -e $activation_path || -L $activation_path ]]; then
      load_activation
      if [[ $activation_previous == none ]]; then
        [[ $activation_incoming == "$release_id" ]] || {
          echo "uncommitted initial release differs from the requested release" >&2
          exit 1
        }
        finish_incoming_activation
        printf '%s\n' "$release_id"
        exit 0
      fi
      # A previous failed deployment has now restored its exact prior release.
      # Keep that durable journal as the recovery authority while copying and
      # fsyncing the next candidate. Replacing it is the new transaction's
      # linearization point; there is never an unjournaled retry window.
      recovered_previous_id=$activation_previous
    fi
    target_set=$(persist_source_set "$source_root" "$release_id" incoming)
    if [[ -n $recovered_previous_id ]]; then
      previous_id=$recovered_previous_id
      verify_active "$previous_id"
    else
      previous_id=none
      active_manifest="$active_release_root/guest-runtime-release-manifest.v1.json"
      if [[ -e $active_manifest || -L $active_manifest ]]; then
        previous_id=$(persist_active_set)
      elif [[ -e $active_release_root/guest-runtime-profile.v1.json \
          || -e $active_guest_root/vmlinuz \
          || -e $active_guest_root/initramfs.img ]]; then
        echo "partial active Guest release exists without its manifest" >&2
        exit 1
      fi
    fi
    write_activation "$release_id" "$previous_id"
    prepare_rollback() {
      local status=$?
      trap - ERR
      rollback_activation || true
      exit "$status"
    }
    trap prepare_rollback ERR
    install_set "$target_set"
    verify_active "$release_id"
    trap - ERR
    printf '%s\n' "$release_id"
    ;;
  authorize-start)
    valid_candidate_token "$argument_1" || exit 2
    valid_decimal "$argument_2" || exit 2
    valid_decimal "$argument_3" || exit 2
    require_process_identity "$argument_2" "$argument_3"
    load_activation
    verify_active "$activation_incoming"
    systemctl is-active --quiet "$deployment_watchdog_service"
    write_start_authorization "$activation_incoming" \
      "$argument_1" "$argument_2" "$argument_3" armed none none
    ;;
  bind-start)
    valid_candidate_token "$argument_1" || exit 2
    valid_decimal "$argument_2" || exit 2
    valid_decimal "$argument_3" || exit 2
    load_activation
    load_start_authorization "$activation_incoming"
    [[ $start_authorization_token == "$argument_1" \
        && $start_authorization_gate == consumed \
        && $start_authorization_main_pid == none \
        && $start_authorization_main_start == none ]] || exit 1
    require_process_identity "$start_authorization_owner_pid" \
      "$start_authorization_owner_start"
    [[ $(current_main_identity) == "$argument_2:$argument_3" ]] || exit 1
    write_start_authorization "$activation_incoming" \
      "$start_authorization_token" "$start_authorization_owner_pid" \
      "$start_authorization_owner_start" consumed "$argument_2" "$argument_3"
    ;;
  commit)
    valid_candidate_token "$argument_1" || exit 2
    valid_decimal "$argument_2" || exit 2
    valid_decimal "$argument_3" || exit 2
    load_activation
    load_start_authorization "$activation_incoming"
    [[ $start_authorization_token == "$argument_1" \
        && $start_authorization_gate == consumed \
        && $start_authorization_main_pid == "$argument_2" \
        && $start_authorization_main_start == "$argument_3" ]] || exit 1
    require_process_identity "$start_authorization_owner_pid" \
      "$start_authorization_owner_start"
    [[ $(current_main_identity) == "$argument_2:$argument_3" ]] || exit 1
    verify_active "$activation_incoming"
    crash_probe "commit-verified-readiness"
    clear_activation
    clear_start_authorization
    ;;
  watchdog-check)
    valid_candidate_token "$argument_1" || exit 2
    valid_decimal "$argument_2" || exit 2
    valid_decimal "$argument_3" || exit 2
    if [[ ! -e $activation_path && ! -L $activation_path ]]; then
      exit 10
    fi
    load_activation
    load_start_authorization "$activation_incoming"
    [[ $start_authorization_token == "$argument_1" \
        && $start_authorization_owner_pid == "$argument_2" \
        && $start_authorization_owner_start == "$argument_3" ]] || exit 1
    ;;
  rollback)
    rollback_activation
    ;;
  recover)
    recover_activation
    ;;
  startup-recover)
    startup_recover
    ;;
esac
