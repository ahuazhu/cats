#!/usr/bin/env bash
# Verify and atomically install the one closed Guest runtime release payload.
set -euo pipefail

mode=${1:-}
source_root=${2:-}
node_service=${CATS_NODE_SERVICE_NAME:-cats-worker}
[[ $mode == verify || $mode == install ]] || {
  echo "usage: $0 verify|install <guest-runtime-release.v1>" >&2
  exit 2
}
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

verify_release() {
  local root=$1
  python3 - "$root" <<'PY'
import hashlib, json, os, stat, sys

root = os.path.abspath(sys.argv[1])
root_metadata = os.lstat(root)
if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
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
                    or metadata.st_uid != 0 or metadata.st_gid != 0
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

release_id=$(verify_release "$source_root")
[[ $mode == verify ]] && { printf '%s\n' "$release_id"; exit 0; }
systemctl is-active --quiet "$node_service" && {
  echo "$node_service must be stopped before Guest release activation" >&2
  exit 1
}

sets_root=/opt/cats/releases/sets
incomplete=/opt/cats/releases/.incomplete
install -d -o root -g root -m 0700 "$sets_root" /opt/cats/releases
rm -rf -- "$incomplete"
install -d -o root -g root -m 0700 "$incomplete"
cp -a -- "$source_root/." "$incomplete/"
find "$incomplete" -type d -exec chmod 0700 {} +
find "$incomplete" -type f -exec chown root:root {} + -exec chmod 0644 {} +
test "$(verify_release "$incomplete")" = "$release_id"
find "$incomplete" -type f -exec sync -f {} +
find "$incomplete" -depth -type d -exec sync -f {} +
target_set="$sets_root/$release_id"
if [[ -e $target_set ]]; then
  test "$(verify_release "$target_set")" = "$release_id"
  rm -rf -- "$incomplete"
else
  mv -T -- "$incomplete" "$target_set"
  sync -f "$sets_root"
fi

install_set() {
  local set=$1 active_path source_path temp
  install -d -o root -g root -m 0755 /opt/cats/release /opt/cats/guest
  while IFS='|' read -r source_path active_path; do
    temp="${active_path}.incoming.$$"
    install -o root -g root -m 0644 "$set/$source_path" "$temp"
    sync -f "$temp"
    mv -fT -- "$temp" "$active_path"
    sync -f "$active_path"
    sync -f "$(dirname "$active_path")"
  done <<'EOF'
guest-runtime-profile.v1.json|/opt/cats/release/guest-runtime-profile.v1.json
guest/vmlinuz|/opt/cats/guest/vmlinuz
EOF
  if [[ -f $set/guest/initramfs.img ]]; then
    temp="/opt/cats/guest/initramfs.img.incoming.$$"
    install -o root -g root -m 0644 "$set/guest/initramfs.img" "$temp"
    sync -f "$temp"
    mv -fT -- "$temp" /opt/cats/guest/initramfs.img
    sync -f /opt/cats/guest/initramfs.img /opt/cats/guest
  else
    rm -f -- /opt/cats/guest/initramfs.img
    sync -f /opt/cats/guest
  fi
  temp="/opt/cats/release/guest-runtime-release-manifest.v1.json.incoming.$$"
  install -o root -g root -m 0644 "$set/manifest.v1.json" "$temp"
  sync -f "$temp"
  mv -fT -- "$temp" /opt/cats/release/guest-runtime-release-manifest.v1.json
  sync -f /opt/cats/release/guest-runtime-release-manifest.v1.json /opt/cats/release
}

materialize_active() {
  local destination=$1
  install -d -o root -g root -m 0700 "$destination/guest"
  install -o root -g root -m 0644 \
    /opt/cats/release/guest-runtime-release-manifest.v1.json \
    "$destination/manifest.v1.json"
  install -o root -g root -m 0644 \
    /opt/cats/release/guest-runtime-profile.v1.json \
    "$destination/guest-runtime-profile.v1.json"
  install -o root -g root -m 0644 /opt/cats/guest/vmlinuz "$destination/guest/vmlinuz"
  if [[ -e /opt/cats/guest/initramfs.img ]]; then
    install -o root -g root -m 0644 \
      /opt/cats/guest/initramfs.img "$destination/guest/initramfs.img"
  fi
}

previous_set=""
if [[ -e /opt/cats/release/guest-runtime-release-manifest.v1.json ]]; then
  previous_incomplete=/opt/cats/releases/.previous.incomplete
  rm -rf -- "$previous_incomplete"
  materialize_active "$previous_incomplete"
  previous_id=$(verify_release "$previous_incomplete")
  previous_set="$sets_root/$previous_id"
  find "$previous_incomplete" -type f -exec sync -f {} +
  find "$previous_incomplete" -depth -type d -exec sync -f {} +
  if [[ -e $previous_set ]]; then
    test "$(verify_release "$previous_set")" = "$previous_id"
    rm -rf -- "$previous_incomplete"
  else
    mv -T -- "$previous_incomplete" "$previous_set"
    sync -f "$sets_root"
  fi
fi

rollback() {
  local status=$?
  trap - ERR
  if [[ -n $previous_set ]]; then
    install_set "$previous_set" || true
  fi
  exit "$status"
}
trap rollback ERR
install_set "$target_set"
active_verification=/opt/cats/releases/.active-verification
rm -rf -- "$active_verification"
materialize_active "$active_verification"
test "$(verify_release "$active_verification")" = "$release_id"
rm -rf -- "$active_verification"
sync -f /opt/cats/releases
trap - ERR
printf '%s\n' "$release_id"
