#!/usr/bin/env bash
# Install only the operator-Host verification toolchain on a dedicated
# operator execution Host:
#
#   /opt/cats/bin/cats
#   /opt/cats/bin/cats-usage-schema-v16-verifier
#   /opt/cats/bin/cats-usage-terminal-receipt-verifier
#   /etc/cats/production-cutover-operator-trust.v1.json
#
# The three executables come from the exact digest-checked release worker
# bundle (cats-worker.tar.zst), so the proof-set consumer can bind them to the
# release manifest worker members. This installer deliberately installs no
# systemd unit, no cloud-hypervisor, no guest payload and no node identity:
# running it never turns an operator Host into a worker.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: install-operator-tools.sh \
  --bundle /absolute/cats-worker.tar.zst \
  --bundle-sha256 <sha256:HEX or HEX from release-manifest.v1.json> \
  --trust-file /absolute/production-cutover-operator-trust.v1.json \
  [--install-root /] [--dry-run] [--replace]

Verifies the worker bundle against its release digest, extracts only the
operator verification toolchain into /opt/cats/bin (root:root 0755, one hard
link each) and installs the public cutover operator trust artifact at
/etc/cats/production-cutover-operator-trust.v1.json (root:root 0644).
A repeated run replays exact content and changes nothing. A different
already-installed file fails closed unless --replace is explicit. --dry-run
performs every validation and prints the plan without any mutation.
--install-root relocates the / prefix for tests; the default requires root.
EOF
}

bundle=
bundle_sha256=
trust_file=
install_root=/
dry_run=false
replace=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      bundle=$2
      shift 2
      ;;
    --bundle-sha256)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      bundle_sha256=$2
      shift 2
      ;;
    --trust-file)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      trust_file=$2
      shift 2
      ;;
    --install-root)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      install_root=$2
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --replace)
      replace=true
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ $bundle == /* && $bundle != *$'\n'* ]] || {
  echo "--bundle must be a newline-free absolute path" >&2
  exit 2
}
[[ $(basename -- "$bundle") == cats-worker.tar.zst ]] || {
  echo "--bundle must use the canonical cats-worker.tar.zst name" >&2
  exit 2
}
[[ -f $bundle && ! -L $bundle ]] || {
  echo "--bundle must name an existing regular file" >&2
  exit 2
}
bundle_sha256=${bundle_sha256#sha256:}
[[ $bundle_sha256 =~ ^[0-9a-f]{64}$ ]] || {
  echo "--bundle-sha256 must be one exact lowercase 64-hex SHA-256" >&2
  exit 2
}
[[ $trust_file == /* && $trust_file != *$'\n'* ]] || {
  echo "--trust-file must be a newline-free absolute path" >&2
  exit 2
}
[[ -f $trust_file && ! -L $trust_file ]] || {
  echo "--trust-file must name an existing regular file" >&2
  exit 2
}
[[ $install_root == /* && $install_root != *$'\n'* ]] || {
  echo "--install-root must be a newline-free absolute path" >&2
  exit 2
}
[[ $install_root == / ]] || install_root=${install_root%/}
[[ -d $install_root && ! -L $install_root ]] || {
  echo "--install-root must be an existing real directory" >&2
  exit 2
}
if [[ $install_root == / && $EUID -ne 0 ]]; then
  echo "run as root (or pass --install-root for a test root)" >&2
  exit 1
fi

for required in cmp install python3 sha256sum tar zstd; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "operator tools installation needs $required" >&2
    exit 1
  }
done

deploy_aws="$(cd "$(dirname "$0")" && pwd)"
trust_tool="$deploy_aws/production-cutover-operator-trust.py"
[[ -f $trust_tool ]] || {
  echo "missing sibling validator: $trust_tool" >&2
  exit 1
}

operator_tools=(
  cats
  cats-usage-schema-v16-verifier
  cats-usage-terminal-receipt-verifier
)
prefix=$install_root
[[ $prefix != / ]] || prefix=
bin_directory="$prefix/opt/cats/bin"
etc_directory="$prefix/etc/cats"
trust_target="$etc_directory/production-cutover-operator-trust.v1.json"

stage=
archive_entries=
cleanup() {
  status=$?
  trap - EXIT INT TERM
  [[ -z $stage ]] || rm -rf -- "$stage"
  [[ -z $archive_entries ]] || rm -f -- "$archive_entries"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The public trust input must already be the exact canonical v1 artifact.
# Reuse the one repository trust validator instead of a second parser.
python3 -B - "$trust_tool" "$trust_file" <<'PY'
import importlib.util
import sys
from pathlib import Path

specification = importlib.util.spec_from_file_location(
    "cats_production_cutover_operator_trust", Path(sys.argv[1])
)
assert specification is not None and specification.loader is not None
module = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = module
specification.loader.exec_module(module)
try:
    raw = module.stable_read(
        Path(sys.argv[2]), "operator trust input", module.MAX_TRUST_BYTES
    )
    module.validate_trust(module.decode_json(raw, "operator trust input"))
except module.TrustError as error:
    print(f"operator trust input refused: {error}", file=sys.stderr)
    raise SystemExit(1)
PY

echo "==> verify worker bundle digest"
printf '%s  %s\n' "$bundle_sha256" "$bundle" | sha256sum --check --strict -

# The same archive preflight as the worker deployment: no absolute paths, no
# parent traversal, no duplicate entries, only regular files and directories.
archive_entries=$(mktemp "${TMPDIR:-/tmp}/cats-operator-tools-entries.XXXXXX")
zstd -dc -- "$bundle" | tar -tf - > "$archive_entries"
awk '
  /^\// || /(^|\/)\.\.($|\/)/ { exit 1 }
  seen[$0]++ { exit 1 }
' "$archive_entries" || {
  echo "worker bundle contains an unsafe or duplicate path" >&2
  exit 1
}
zstd -dc -- "$bundle" | tar -tvf - | awk 'substr($1,1,1) !~ /^[-d]$/ { exit 1 }' || {
  echo "worker bundle contains a link or special member" >&2
  exit 1
}
for name in "${operator_tools[@]}"; do
  grep -qx -- "./$name" "$archive_entries" || {
    echo "worker bundle misses the operator tool member: $name" >&2
    exit 1
  }
done

stage=$(mktemp -d "${TMPDIR:-/tmp}/cats-operator-tools-stage.XXXXXX")
chmod 0700 "$stage"
echo "==> extract operator toolchain members"
member_arguments=()
for name in "${operator_tools[@]}"; do
  member_arguments+=("./$name")
done
zstd -dc -- "$bundle" | tar -xf - -C "$stage" "${member_arguments[@]}"
for name in "${operator_tools[@]}"; do
  [[ -f $stage/$name && ! -L $stage/$name && -s $stage/$name ]] || {
    echo "extracted operator tool member is invalid: $name" >&2
    exit 1
  }
done

# exact_installed TARGET SOURCE MODE -> 0 only when the installed file is a
# byte-identical single-hard-link regular file with the exact mode (and
# root:root under a real-root install).
exact_installed() {
  local target=$1 source=$2 mode=$3
  [[ -f $target && ! -L $target ]] || return 1
  cmp -s -- "$source" "$target" || return 1
  python3 -B - "$target" "$mode" "$EUID" <<'PY'
import os
import stat
import sys

metadata = os.lstat(sys.argv[1])
expected_mode = int(sys.argv[2], 8)
require_root = int(sys.argv[3]) == 0
ok = (
    stat.S_ISREG(metadata.st_mode)
    and stat.S_IMODE(metadata.st_mode) == expected_mode
    and metadata.st_nlink == 1
    and (not require_root or (metadata.st_uid == 0 and metadata.st_gid == 0))
)
raise SystemExit(0 if ok else 1)
PY
}

owner_arguments=()
[[ $EUID -ne 0 ]] || owner_arguments=(-o root -g root)

plan_sources=()
plan_targets=()
plan_modes=()
plan_actions=()
conflicts=0
add_plan() {
  local source=$1 target=$2 mode=$3 action
  if [[ -L $target ]]; then
    action=conflict
  elif [[ ! -e $target ]]; then
    action=install
  elif exact_installed "$target" "$source" "$mode"; then
    action=exact
  else
    action=conflict
  fi
  if [[ $action == conflict ]]; then
    if [[ $replace == true ]]; then
      action=replace
    else
      conflicts=$((conflicts + 1))
      echo "already installed and different: $target (rerun with --replace)" >&2
    fi
  fi
  plan_sources+=("$source")
  plan_targets+=("$target")
  plan_modes+=("$mode")
  plan_actions+=("$action")
}

for name in "${operator_tools[@]}"; do
  add_plan "$stage/$name" "$bin_directory/$name" 0755
done
add_plan "$trust_file" "$trust_target" 0644

if [[ $conflicts -gt 0 ]]; then
  echo "refusing to overwrite $conflicts existing different file(s) without --replace" >&2
  exit 1
fi

if [[ $dry_run == true ]]; then
  echo "==> dry run; no file was changed"
  for index in "${!plan_targets[@]}"; do
    case "${plan_actions[$index]}" in
      install) echo "would install ${plan_targets[$index]}" ;;
      replace) echo "would replace ${plan_targets[$index]}" ;;
      exact) echo "already exact ${plan_targets[$index]}" ;;
    esac
  done
  exit 0
fi

ensure_directory() {
  local directory=$1
  [[ ! -L $directory ]] || {
    echo "refusing symlinked install directory: $directory" >&2
    exit 1
  }
  [[ -d $directory ]] || install -d "${owner_arguments[@]}" -m 0755 "$directory"
}
ensure_directory "$prefix/opt"
ensure_directory "$prefix/opt/cats"
ensure_directory "$bin_directory"
ensure_directory "$prefix/etc"
ensure_directory "$etc_directory"

for index in "${!plan_targets[@]}"; do
  target=${plan_targets[$index]}
  source=${plan_sources[$index]}
  mode=${plan_modes[$index]}
  case "${plan_actions[$index]}" in
    exact)
      echo "==> already exact: $target"
      continue
      ;;
    replace)
      echo "==> replace: $target"
      rm -f -- "$target"
      ;;
    install)
      echo "==> install: $target"
      ;;
  esac
  install "${owner_arguments[@]}" -m "$mode" -- "$source" "$target"
  exact_installed "$target" "$source" "$mode" || {
    echo "installed file failed its post-install verification: $target" >&2
    exit 1
  }
  # Durable before this run's success output; sync -f is Linux-only.
  python3 -B -c '
import os
import sys

for path in (sys.argv[1], os.path.dirname(sys.argv[1])):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
' "$target"
done

echo "==> installed operator toolchain"
for index in "${!plan_targets[@]}"; do
  sha256sum -- "${plan_targets[$index]}"
done
