#!/usr/bin/env bash
# Run-wide Usage terminal finalizer. Both block-path qualifications must have
# completed before this script is invoked. It performs no product mutation: it
# consumes their immutable source-terminal evidence and closes the old Usage
# target exactly once.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: runtime-cutover-usage-terminal-finalize.sh \
  --exact-commit <40 lowercase hex> \
  --output-dir </absolute/new-or-replay-directory> \
  --kernel-nbd-qualification-dir </absolute/passed-directory> \
  --vhost-user-qualification-dir </absolute/passed-directory> \
  --release-manifest </absolute/release-manifest.json> \
  --release-manifest-sha256 <sha256:64hex> \
  --installer-receipt </absolute/installer-receipt.json> \
  --qualification-catalog </absolute/qualification-catalog.v1.json> \
  --usage-terminal-targets </absolute/root-only/usage-terminal-targets.json> \
  --usage-terminal-targets-sha256 <sha256:64hex> \
  --token-file </absolute/root-only/control-token> \
  --control-origin <canonical-https-origin>
EOF
  exit 64
}

fail() {
  printf 'runtime cutover usage terminal finalizer: %s\n' "$*" >&2
  exit 64
}

set_once() {
  local name=$1 value=$2
  [[ -z ${!name} ]] || fail "--${name//_/-} is repeated"
  [[ -n $value ]] || fail "--${name//_/-} is empty"
  printf -v "$name" '%s' "$value"
}

exact_commit=
output_dir=
kernel_nbd_qualification_dir=
vhost_user_qualification_dir=
release_manifest=
release_manifest_sha256=
installer_receipt=
qualification_catalog=
usage_terminal_targets=
usage_terminal_targets_sha256=
token_file=
control_origin=

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exact-commit|--output-dir|--kernel-nbd-qualification-dir|--vhost-user-qualification-dir|--release-manifest|--release-manifest-sha256|--installer-receipt|--qualification-catalog|--usage-terminal-targets|--usage-terminal-targets-sha256|--token-file|--control-origin)
      [[ $# -ge 2 ]] || usage
      option=${1#--}
      option=${option//-/_}
      set_once "$option" "$2"
      shift 2
      ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ $exact_commit =~ ^[0-9a-f]{40}$ ]] || fail "--exact-commit is not one exact commit"
[[ $release_manifest_sha256 =~ ^sha256:[0-9a-f]{64}$ ]] || \
  fail "--release-manifest-sha256 is not canonical"
[[ $usage_terminal_targets_sha256 =~ ^sha256:[0-9a-f]{64}$ ]] || \
  fail "--usage-terminal-targets-sha256 is not canonical"
[[ $control_origin =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || \
  fail "--control-origin is not one canonical HTTPS origin"
for path_name in output_dir kernel_nbd_qualification_dir vhost_user_qualification_dir \
  release_manifest installer_receipt qualification_catalog usage_terminal_targets token_file; do
  [[ ${!path_name} == /* ]] || fail "--${path_name//_/-} must be absolute"
done
[[ $EUID -eq 0 ]] || fail "the production finalizer must run as root"
for command_name in awk date env git jq python3 sha256sum sleep stat wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

script_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$script_dir/../.." && pwd -P)
finalizer=$script_dir/runtime-cutover-usage-terminal-finalize.sh
[[ $(git -C "$repo" rev-parse HEAD) == "$exact_commit" ]] || \
  fail "checkout HEAD does not equal --exact-commit"
[[ $(git -C "$repo" rev-parse "${exact_commit}^{commit}") == "$exact_commit" ]] || \
  fail "--exact-commit does not resolve to one commit object"
finalizer_relative=${finalizer#"$repo"/}
[[ $finalizer_relative != "$finalizer" ]] || fail "finalizer is not repo-owned"
expected_finalizer_blob=$(git -C "$repo" rev-parse "${exact_commit}:${finalizer_relative}" 2>/dev/null) || \
  fail "finalizer is absent from the exact commit"
[[ $(git -C "$repo" hash-object "$finalizer") == "$expected_finalizer_blob" ]] || \
  fail "running finalizer differs from the exact commit"
case "$qualification_catalog" in "$repo"/*) ;; *) fail "qualification catalog is not repo-owned" ;; esac
catalog_relative=${qualification_catalog#"$repo"/}
expected_catalog_blob=$(git -C "$repo" rev-parse "${exact_commit}:${catalog_relative}" 2>/dev/null) || \
  fail "qualification catalog is absent from the exact commit"
[[ $(git -C "$repo" hash-object "$qualification_catalog") == "$expected_catalog_blob" ]] || \
  fail "qualification catalog differs from the exact commit"

output_parent=${output_dir%/*}
output_name=${output_dir##*/}
[[ -n $output_parent && -n $output_name && $output_name != . && $output_name != .. ]] || \
  fail "--output-dir is not canonical"
[[ -d $output_parent && ! -L $output_parent ]] || fail "output parent is unavailable"
if ! python3 - "$output_parent" <<'PY'
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
    raise SystemExit(1)
current = Path(path.root)
for component in path.parts[1:]:
    current /= component
    metadata = os.lstat(current)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise SystemExit(1)
PY
then
  fail "output parent has an unsafe directory chain"
fi
if [[ ! -e $output_dir && ! -L $output_dir ]]; then
  mkdir -m 0700 "$output_dir"
fi
[[ -d $output_dir && ! -L $output_dir ]] || fail "output path is not a directory"
[[ $(stat -c '%a:%u:%g' "$output_dir") == 700:0:0 ]] || \
  fail "output directory must remain root-owned mode 0700"

allowed_outputs='|case-evidence.jsonl|qualification-catalog.v1.json|SHA256SUMS|usage-global-terminal-finalization.manifest.json|usage-target-terminal-receipt.json|usage-target-terminal-request.json|usage-target-terminal-verification.receipt.json|usage-terminal-targets.json|'
allowed_pending='|.case-evidence.jsonl.pending|.qualification-catalog.v1.json.pending|.SHA256SUMS.pending|.usage-global-terminal-finalization.manifest.json.pending|.usage-target-terminal-receipt.json.pending|.usage-target-terminal-request.json.pending|.usage-target-terminal-verification.receipt.json.pending|.usage-terminal-targets.json.pending|'
shopt -s nullglob dotglob
for existing_output in "$output_dir"/*; do
  existing_name=${existing_output##*/}
  case "$allowed_outputs" in
    *"|$existing_name|"*) ;;
    *)
      case "$allowed_pending" in
        *"|$existing_name|"*) ;;
        *) fail "output directory contains foreign entry $existing_name" ;;
      esac
      ;;
  esac
done
shopt -u nullglob dotglob

private_parent=${token_file%/*}
[[ -d $private_parent && ! -L $private_parent ]] || fail "token parent is unavailable"
private_stage=$(mktemp -d "$private_parent/.cats-usage-terminal-finalize.XXXXXX")
chmod 0700 "$private_stage"
cleanup_private_stage() {
  local status=$?
  trap - EXIT INT TERM
  rm -rf -- "$private_stage" || status=125
  exit "$status"
}
trap cleanup_private_stage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

preflight=$private_stage/preflight.json
if ! python3 - "$exact_commit" "$kernel_nbd_qualification_dir" \
  "$vhost_user_qualification_dir" "$release_manifest" "$release_manifest_sha256" \
  "$installer_receipt" "$qualification_catalog" "$usage_terminal_targets" \
  "$usage_terminal_targets_sha256" "$token_file" "$control_origin" >"$preflight" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

CONTROL_SCHEMA_VERSION = 19

(
    exact_commit,
    kernel_dir_raw,
    vhost_dir_raw,
    release_path_raw,
    release_sha256,
    installer_path_raw,
    catalog_path_raw,
    targets_path_raw,
    targets_sha256,
    token_path_raw,
    control_origin,
) = sys.argv[1:]

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
RUN_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
WIRE_MAX = (1 << 64) - 1
COUNT_MAX = (1 << 63) - 1
BASE_RUN_FILES = {
    "SHA256SUMS",
    "case-evidence.jsonl",
    "component-journal-summary.txt",
    "exit-code",
    "final-inventory.json",
    "manifest.json",
    "qualification-catalog.v1.json",
    "runtime-state.json",
    "scenario-results.jsonl",
}
QUALIFICATION_BEGIN_FILE = "production-mutation-qualification-begin.receipt.json"
QUALIFICATION_TERMINAL_FILE = "production-mutation-qualification-terminal.receipt.json"
QUALIFICATION_BEGIN_PENDING_FILE = "production-mutation-qualification-begin.pending.json"
QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE = (
    "production-mutation-qualification-begin.command-receipt.json"
)
QUALIFICATION_CLOSE_PENDING_FILE = "production-mutation-qualification-close.pending.json"
QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE = (
    "production-mutation-qualification-close.command-receipt.json"
)
QUALIFICATION_FINAL_STATE_FILE = (
    "production-mutation-qualification-final-admission-state.json"
)
QUALIFICATION_FINAL_FLEET_FILE = (
    "production-mutation-qualification-final-fleet-closed.receipt.json"
)
QUALIFICATION_CLEANUP_INVENTORY_FILE = (
    "production-mutation-qualification-cleanup-inventory.receipt.json"
)
QUALIFICATION_PRODUCT_INVENTORY_FILE = (
    "production-mutation-qualification-product-inventory.receipt.json"
)
QUALIFICATION_SUPPORT_FILES = {
    QUALIFICATION_BEGIN_FILE,
    QUALIFICATION_TERMINAL_FILE,
    QUALIFICATION_BEGIN_PENDING_FILE,
    QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE,
    QUALIFICATION_CLOSE_PENDING_FILE,
    QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE,
    QUALIFICATION_FINAL_STATE_FILE,
    QUALIFICATION_FINAL_FLEET_FILE,
    QUALIFICATION_CLEANUP_INVENTORY_FILE,
    QUALIFICATION_PRODUCT_INVENTORY_FILE,
}
EXPECTED_RUN_FILES = BASE_RUN_FILES | QUALIFICATION_SUPPORT_FILES
CHECKSUM_FILES = sorted(EXPECTED_RUN_FILES - {"SHA256SUMS"})
QUALIFICATION_REQUIRED_EVIDENCE = [
    {"filename": QUALIFICATION_BEGIN_FILE, "kind": "json"},
    {"filename": QUALIFICATION_TERMINAL_FILE, "kind": "json"},
]
QUALIFICATION_MUTATION_CLASSES = [
    "cat_create",
    "disk_create",
    "disk_delete",
    "runtime_mutation",
]
SOURCE_CASE = "usage-source-terminal-receipts"


class DuplicateKey(ValueError):
    pass


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey(key)
        value[key] = item
    return value


def compact(value, *, ascii_only=False):
    return json.dumps(
        value,
        ensure_ascii=ascii_only,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


# SOURCE_SET_CANONICAL_BEGIN
def typed_source_set_bytes(sources):
    if not isinstance(sources, list) or not sources:
        raise ValueError("Usage source set is empty")
    normalized = []
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "receipt_sha256", "source_epoch", "source_id"
        }:
            raise ValueError("Usage source expectation has a foreign shape")
        normalized.append({
            "source_id": source["source_id"],
            "source_epoch": source["source_epoch"],
            "receipt_sha256": source["receipt_sha256"],
        })
    return json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def typed_source_set_sha256(sources):
    return "sha256:" + hashlib.sha256(typed_source_set_bytes(sources)).hexdigest()
# SOURCE_SET_CANONICAL_END


def safe_path(raw, kind, modes, maximum=None, root_owned=True):
    path = Path(raw)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ValueError(f"{kind} path is not canonical absolute")
    current = Path(path.root)
    for component in path.parts[1:]:
        current /= component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{kind} path contains a symlink")
        if current != path and (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or root_owned and (metadata.st_uid != 0 or metadata.st_gid != 0)
        ):
            raise ValueError(f"{kind} has an unsafe directory chain")
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{kind} is not one regular file")
    if root_owned and (metadata.st_uid != 0 or metadata.st_gid != 0):
        raise ValueError(f"{kind} is not root-owned")
    if stat.S_IMODE(metadata.st_mode) not in modes:
        raise ValueError(f"{kind} mode is outside the closed set")
    if metadata.st_size <= 0 or (maximum is not None and metadata.st_size > maximum):
        raise ValueError(f"{kind} size is outside the closed bound")
    return path


def safe_dir(raw, kind):
    path = Path(raw)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise ValueError(f"{kind} path is not canonical absolute")
    current = Path(path.root)
    for component in path.parts[1:]:
        current /= component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"{kind} path is not a real directory")
        if current != path and (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ValueError(f"{kind} has an unsafe directory chain")
    metadata = os.lstat(path)
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError(f"{kind} must be root-owned mode 0700")
    return path


def load_json(path, kind, maximum=1_048_576, canonical=None):
    raw = path.read_bytes()
    if not 1 <= len(raw) <= maximum:
        raise ValueError(f"{kind} exceeds its byte bound")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_object)
    if canonical == "compact" and raw != compact(value) + b"\n":
        raise ValueError(f"{kind} is not canonical compact JSON")
    if canonical == "cats" and raw not in {compact(value), compact(value) + b"\n"}:
        raise ValueError(f"{kind} is not canonical Cats JSON")
    if canonical == "cats-no-lf" and raw != compact(value):
        raise ValueError(f"{kind} is not canonical Cats wire JSON")
    if canonical == "pretty":
        expected = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
        if raw != expected:
            raise ValueError(f"{kind} is not canonical pretty JSON")
    return value, raw


def load_json_lines(path, kind, maximum=32 * 1_048_576):
    raw = path.read_bytes()
    if not 1 <= len(raw) <= maximum or not raw.endswith(b"\n"):
        raise ValueError(f"{kind} is outside its closed JSONL bound")
    values = []
    for line in raw.splitlines(keepends=True):
        value = json.loads(line.decode("utf-8"), object_pairs_hook=closed_object)
        if line != compact(value) + b"\n":
            raise ValueError(f"{kind} has a noncanonical row")
        values.append(value)
    return values, raw


release_path = safe_path(release_path_raw, "release manifest", {0o600, 0o644}, 1_048_576, False)
installer_path = safe_path(installer_path_raw, "installer receipt", {0o600, 0o644}, 1_048_576)
catalog_path = safe_path(catalog_path_raw, "qualification catalog", {0o600, 0o644}, 1_048_576, False)
targets_path = safe_path(targets_path_raw, "Usage target descriptor", {0o400, 0o600}, 1_048_576)
token_path = safe_path(token_path_raw, "control token", {0o600}, 16_384)
token = token_path.read_bytes()
if token.endswith(b"\n"):
    token = token[:-1]
if not token or any(value in token for value in (b"\n", b"\r", b"\0")):
    raise ValueError("control token is not one header-safe line")

release, release_raw = load_json(release_path, "release manifest")
if sha(release_raw) != release_sha256:
    raise ValueError("release manifest differs from its approved digest")
if release.get("version") != 1 or release.get("source", {}).get("commit") != exact_commit:
    raise ValueError("release manifest does not bind the exact commit")
worker = release.get("artifacts", {}).get("worker", {})
worker_bundle_sha256 = worker.get("bundle_sha256")
members = worker.get("members")
if not isinstance(worker_bundle_sha256, str) or not DIGEST.fullmatch(worker_bundle_sha256):
    raise ValueError("release worker bundle digest is invalid")
if not isinstance(members, dict) or "cats-usage-terminal-receipt-verifier" not in members:
    raise ValueError("release omits the terminal receipt verifier")

installer, installer_raw = load_json(installer_path, "installer receipt", canonical="compact")
if set(installer) != {"host_tools", "members", "service", "version", "worker_bundle_sha256"}:
    raise ValueError("installer receipt has a foreign top-level shape")
if installer["version"] != 1 or installer["service"] != "cats-worker.service":
    raise ValueError("installer receipt has a foreign version or service")
if installer["worker_bundle_sha256"] != worker_bundle_sha256:
    raise ValueError("installer and release worker bundles differ")
if set(installer["members"]) != set(members):
    raise ValueError("installer and release worker member sets differ")
for name, installed in installer["members"].items():
    if set(installed) != {"path", "sha256", "size_bytes"}:
        raise ValueError("installer worker member has a foreign shape")
    released = members[name]
    if installed["sha256"] != released.get("sha256") or installed["size_bytes"] != released.get("size_bytes"):
        raise ValueError("installed worker member differs from the release")
if set(installer["host_tools"]) != {"curl", "journalctl", "systemctl", "timeout"}:
    raise ValueError("installer host-tool set is foreign")
for tool in installer["host_tools"].values():
    if set(tool) != {"path", "sha256", "size_bytes"}:
        raise ValueError("installer host tool has a foreign shape")


def installed_executable(record, exact_path=None):
    path = safe_path(record["path"], "installed executable", {0o755}, 512 * 1_048_576)
    if exact_path is not None and str(path) != exact_path:
        raise ValueError("installed executable path is not the frozen production path")
    raw = path.read_bytes()
    if sha(raw) != record["sha256"] or len(raw) != record["size_bytes"]:
        raise ValueError("installed executable bytes differ from the receipt")
    return str(path), record["sha256"]


curl_path, _ = installed_executable(installer["host_tools"]["curl"])
timeout_path, _ = installed_executable(installer["host_tools"]["timeout"])
verifier_path, verifier_sha256 = installed_executable(
    installer["members"]["cats-usage-terminal-receipt-verifier"],
    "/opt/cats/bin/cats-usage-terminal-receipt-verifier",
)

catalog, catalog_raw = load_json(catalog_path, "qualification catalog", canonical="pretty")
qualification_catalog_sha256 = sha(catalog_raw)
if set(catalog) != {
    "cases", "framework_required_evidence", "post_block_path_cases",
    "qualification_admission_required_evidence", "version",
}:
    raise ValueError("qualification catalog top-level shape is foreign")
if (
    catalog["version"] != 1
    or catalog["qualification_admission_required_evidence"]
    != QUALIFICATION_REQUIRED_EVIDENCE
    or catalog["post_block_path_cases"] != [{
    "case_id": "usage-target-terminal-receipt",
    "deadline_seconds": 600,
    "expected_outcome": {"kind": "passed"},
    "required_evidence": [
        {"filename": "usage-target-terminal-request.json", "kind": "json"},
        {"filename": "usage-target-terminal-receipt.json", "kind": "json"},
        {"filename": "usage-target-terminal-verification.receipt.json", "kind": "json"},
    ],
}]
):
    raise ValueError("qualification catalog post-block-path case is foreign")

targets, targets_raw = load_json(targets_path, "Usage target descriptor", canonical="compact")
if sha(targets_raw) != targets_sha256:
    raise ValueError("Usage target descriptor differs from its approved digest")
if set(targets) != {"fresh_target", "old_target", "shards", "version"} or targets["version"] != 1:
    raise ValueError("Usage target descriptor has a foreign shape")
target_keys = {
    "archive_bucket_arn", "archive_bucket_name", "aws_account_id", "aws_region",
    "checkpoint_table_arn", "checkpoint_table_name", "stream_arn", "stream_name", "usage_schema",
}
for target in (targets["old_target"], targets["fresh_target"]):
    if not isinstance(target, dict) or set(target) != target_keys or not all(
        isinstance(value, str) and value for value in target.values()
    ):
        raise ValueError("Usage target binding is not closed")
shards = targets["shards"]
if not isinstance(shards, list) or not shards:
    raise ValueError("Usage shard target set is empty")
for shard in shards:
    if not isinstance(shard, dict) or set(shard) != {"explicit_hash_key", "shard_id"}:
        raise ValueError("Usage shard target has a foreign shape")
    if re.fullmatch(r"shardId-[0-9]{12}", shard["shard_id"]) is None or re.fullmatch(
        r"0|[1-9][0-9]{0,38}", shard["explicit_hash_key"]
    ) is None:
        raise ValueError("Usage shard target is not canonical")
if [item["shard_id"] for item in shards] != sorted({item["shard_id"] for item in shards}):
    raise ValueError("Usage shard targets are not strictly sorted")
target_binding_sha256 = sha(compact(targets))


# QUALIFICATION_CLOSED_SUPPORT_BEGIN
def validate_exact_run_file_names(names):
    if set(names) != EXPECTED_RUN_FILES or len(names) != len(EXPECTED_RUN_FILES):
        raise ValueError("qualification directory is not the exact closed artifact set")


def require_fields(value, expected, kind):
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{kind} has a foreign shape")
    return value


def require_digest(value, kind):
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError(f"{kind} is not a canonical digest")
    return value


def positive_integer(value, kind):
    if type(value) is not int or not 1 <= value <= WIRE_MAX:
        raise ValueError(f"{kind} is not a positive integer")
    return value


def zero(value, kind):
    if type(value) is not int or value != 0:
        raise ValueError(f"{kind} is not zero")


def support_sha256(directory, filename):
    return sha((directory / filename).read_bytes())


def validate_qualification_closed_support(
    directory,
    manifest,
    run_id,
    workspace_id,
    expected_block_path,
):
    begin, begin_raw = load_json(
        directory / QUALIFICATION_BEGIN_FILE,
        "Qualification Begin receipt",
        canonical="cats-no-lf",
    )
    terminal, terminal_raw = load_json(
        directory / QUALIFICATION_TERMINAL_FILE,
        "Qualification terminal receipt",
        canonical="cats-no-lf",
    )
    product, product_raw = load_json(
        directory / QUALIFICATION_PRODUCT_INVENTORY_FILE,
        "Qualification product inventory receipt",
        canonical="cats-no-lf",
    )
    cleanup, cleanup_raw = load_json(
        directory / QUALIFICATION_CLEANUP_INVENTORY_FILE,
        "Qualification cleanup inventory receipt",
        canonical="cats",
    )
    final_state, final_state_raw = load_json(
        directory / QUALIFICATION_FINAL_STATE_FILE,
        "Qualification final admission state",
        canonical="cats-no-lf",
    )
    fleet, fleet_raw = load_json(
        directory / QUALIFICATION_FINAL_FLEET_FILE,
        "Qualification final Fleet Closed receipt",
        canonical="cats",
    )

    begin_fields = {
        "kind", "version", "qualification_id", "workspace_id", "release_id",
        "source_commit_sha", "qualification_catalog_sha256",
        "allowed_mutation_classes", "binding_sha256", "begin_command_id",
        "begin_request_sha256", "begin_command_receipt_sha256",
        "resulting_revision", "qualification_expires_at_unix_ms",
    }
    terminal_fields = {
        "kind", "version", "qualification_id", "workspace_id", "release_id",
        "source_commit_sha", "qualification_catalog_sha256",
        "allowed_mutation_classes", "qualification_expires_at_unix_ms",
        "binding_sha256", "begin_command_id", "begin_request_sha256",
        "begin_command_receipt_sha256", "begin_resulting_revision", "close_kind",
        "terminal_outcome", "close_command_id", "close_request_sha256",
        "close_command_receipt_sha256", "final_admission_state_sha256",
        "final_closed_revision", "fleet_closed_receipt_sha256",
        "product_inventory_receipt_sha256", "cleanup_inventory_receipt_sha256",
        "active_guard_count", "product_resource_count", "residue_count",
        "completed_at_unix_ms",
    }
    require_fields(begin, begin_fields, "Qualification Begin receipt")
    require_fields(terminal, terminal_fields, "Qualification terminal receipt")
    if (
        begin["kind"] != "cats.production-mutation-qualification-begin-receipt.v1"
        or type(begin["version"]) is not int
        or begin["version"] != 1
        or begin["qualification_id"] != run_id
        or begin["workspace_id"] != workspace_id
        or begin["source_commit_sha"] != exact_commit
        or begin["qualification_catalog_sha256"] != qualification_catalog_sha256
        or begin["allowed_mutation_classes"] != QUALIFICATION_MUTATION_CLASSES
        or not isinstance(begin["release_id"], str)
        or ID.fullmatch(begin["release_id"]) is None
        or not isinstance(begin["begin_command_id"], str)
        or re.fullmatch(r"[0-9a-f]{32}", begin["begin_command_id"]) is None
    ):
        raise ValueError("Qualification Begin receipt binding differs")
    for field in (
        "binding_sha256", "begin_request_sha256", "begin_command_receipt_sha256",
    ):
        require_digest(begin[field], f"Qualification Begin {field}")
    begin_revision = positive_integer(
        begin["resulting_revision"], "Qualification Begin resulting revision"
    )
    positive_integer(
        begin["qualification_expires_at_unix_ms"], "Qualification expiry"
    )

    shared_terminal = {
        "qualification_id": "qualification_id",
        "workspace_id": "workspace_id",
        "release_id": "release_id",
        "source_commit_sha": "source_commit_sha",
        "qualification_catalog_sha256": "qualification_catalog_sha256",
        "allowed_mutation_classes": "allowed_mutation_classes",
        "qualification_expires_at_unix_ms": "qualification_expires_at_unix_ms",
        "binding_sha256": "binding_sha256",
        "begin_command_id": "begin_command_id",
        "begin_request_sha256": "begin_request_sha256",
        "begin_command_receipt_sha256": "begin_command_receipt_sha256",
    }
    if any(terminal[field] != begin[source] for field, source in shared_terminal.items()):
        raise ValueError("Qualification terminal receipt rebound its Begin authority")
    if (
        terminal["kind"]
        != "cats.production-mutation-qualification-terminal-receipt.v1"
        or type(terminal["version"]) is not int
        or terminal["version"] != 1
        or terminal["begin_resulting_revision"] != begin_revision
        or terminal["final_closed_revision"] != begin_revision + 1
        or terminal["close_kind"] != "end_qualification"
        or terminal["terminal_outcome"] != "qualified_closed"
        or not isinstance(terminal["close_command_id"], str)
        or re.fullmatch(r"[0-9a-f]{32}", terminal["close_command_id"]) is None
        or terminal["close_command_id"] == begin["begin_command_id"]
    ):
        raise ValueError("Qualification did not reach exact End -> qualified_closed")
    for field in (
        "close_request_sha256", "close_command_receipt_sha256",
        "final_admission_state_sha256", "fleet_closed_receipt_sha256",
        "product_inventory_receipt_sha256", "cleanup_inventory_receipt_sha256",
    ):
        require_digest(terminal[field], f"Qualification terminal {field}")
    for field in ("active_guard_count", "product_resource_count", "residue_count"):
        zero(terminal[field], f"Qualification terminal {field}")
    completed_at = positive_integer(
        terminal["completed_at_unix_ms"], "Qualification terminal completion time"
    )

    actual_support_digests = {
        "begin_command_receipt_sha256": support_sha256(
            directory, QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE
        ),
        "close_command_receipt_sha256": support_sha256(
            directory, QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE
        ),
        "final_admission_state_sha256": sha(final_state_raw),
        "fleet_closed_receipt_sha256": sha(fleet_raw),
        "product_inventory_receipt_sha256": sha(product_raw),
        "cleanup_inventory_receipt_sha256": sha(cleanup_raw),
    }
    if begin["begin_command_receipt_sha256"] != actual_support_digests[
        "begin_command_receipt_sha256"
    ]:
        raise ValueError("Qualification Begin command receipt digest differs")
    if any(
        terminal[field] != actual_support_digests[field]
        for field in actual_support_digests
        if field != "begin_command_receipt_sha256"
    ):
        raise ValueError("Qualification terminal support digest differs")

    required_manifest_evidence = [
        {
            "filename": QUALIFICATION_BEGIN_FILE,
            "kind": "json",
            "sha256": sha(begin_raw),
            "size_bytes": len(begin_raw),
        },
        {
            "filename": QUALIFICATION_TERMINAL_FILE,
            "kind": "json",
            "sha256": sha(terminal_raw),
            "size_bytes": len(terminal_raw),
        },
    ]
    if manifest.get("qualification_admission_required_evidence") != required_manifest_evidence:
        raise ValueError("qualification manifest does not bind exact admission evidence")

    product_fields = {
        "kind", "version", "qualification_id", "workspace_id", "release_id",
        "source_commit_sha", "qualification_catalog_sha256", "binding_sha256",
        "close_kind", "close_command_id", "close_request_sha256",
        "close_command_receipt_sha256", "closed_revision", "evaluated_at_unix_ms",
        "complete", "counts", "product_resource_count",
    }
    count_fields = {
        "current_cat_count", "root_disk_count", "persistent_disk_count",
        "disk_snapshot_count", "endpoint_count", "hostname_desired_lookup_count",
        "pending_runtime_operation_count", "deleted_cat_tombstone_count",
        "terminal_runtime_operation_history_count", "api_idempotency_receipt_count",
    }
    require_fields(product, product_fields, "Qualification product inventory receipt")
    counts = require_fields(product["counts"], count_fields, "Qualification product counts")
    if any(
        type(value) is not int or not 0 <= value <= COUNT_MAX
        for value in counts.values()
    ):
        raise ValueError("Qualification product inventory count is invalid")
    current_count_fields = (
        "current_cat_count", "root_disk_count", "persistent_disk_count",
        "disk_snapshot_count", "endpoint_count", "hostname_desired_lookup_count",
        "pending_runtime_operation_count",
    )
    current_total = sum(counts[field] for field in current_count_fields)
    if (
        product["kind"] != "cats.production-mutation-qualification-product-inventory.v1"
        or type(product["version"]) is not int
        or product["version"] != 1
        or product["qualification_id"] != run_id
        or product["workspace_id"] != workspace_id
        or product["release_id"] != begin["release_id"]
        or product["source_commit_sha"] != exact_commit
        or product["qualification_catalog_sha256"] != qualification_catalog_sha256
        or product["binding_sha256"] != begin["binding_sha256"]
        or product["close_kind"] != "end_qualification"
        or product["close_command_id"] != terminal["close_command_id"]
        or product["close_request_sha256"] != terminal["close_request_sha256"]
        or product["close_command_receipt_sha256"]
        != terminal["close_command_receipt_sha256"]
        or product["closed_revision"] != terminal["final_closed_revision"]
        or product["complete"] is not True
        or type(product["product_resource_count"]) is not int
        or not 0 <= product["product_resource_count"] <= COUNT_MAX
        or product["product_resource_count"] != current_total
        or current_total != 0
    ):
        raise ValueError("Qualification product inventory is not exact and empty")
    product_evaluated_at = positive_integer(
        product["evaluated_at_unix_ms"], "Qualification product inventory time"
    )

    cleanup_fields = {
        "kind", "version", "qualification_id", "workspace_id", "source_commit_sha",
        "block_path", "evaluated_at_unix_ms", "complete",
        "product_inventory_receipt_sha256", "product_resource_count",
        "desired_runtime_count", "current_runtime_observation_count",
        "active_guard_count", "residue_count",
    }
    require_fields(cleanup, cleanup_fields, "Qualification cleanup inventory receipt")
    if (
        cleanup["kind"] != "cats.production-mutation-qualification-cleanup-inventory.v1"
        or type(cleanup["version"]) is not int
        or cleanup["version"] != 1
        or cleanup["qualification_id"] != run_id
        or cleanup["workspace_id"] != workspace_id
        or cleanup["source_commit_sha"] != exact_commit
        or cleanup["block_path"] != expected_block_path
        or cleanup["complete"] is not True
        or cleanup["product_inventory_receipt_sha256"] != sha(product_raw)
        or cleanup["product_resource_count"] != product["product_resource_count"]
    ):
        raise ValueError("Qualification cleanup inventory binding differs")
    for field in (
        "product_resource_count", "desired_runtime_count",
        "current_runtime_observation_count", "active_guard_count", "residue_count",
    ):
        zero(cleanup[field], f"Qualification cleanup {field}")
    cleanup_evaluated_at = positive_integer(
        cleanup["evaluated_at_unix_ms"], "Qualification cleanup time"
    )

    fleet_fields = {
        "kind", "version", "qualification_id", "workspace_id", "source_commit_sha",
        "block_path", "evaluated_at_unix_ms", "complete", "expected_node_ids",
        "desired_runtime_count", "current_runtime_observation_count",
        "active_guard_count", "residue_count", "fleet_verification_receipt_sha256",
    }
    require_fields(fleet, fleet_fields, "Qualification final Fleet Closed receipt")
    expected_nodes = fleet["expected_node_ids"]
    if (
        fleet["kind"] != "cats.production-mutation-qualification-final-fleet-closed.v1"
        or type(fleet["version"]) is not int
        or fleet["version"] != 1
        or fleet["qualification_id"] != run_id
        or fleet["workspace_id"] != workspace_id
        or fleet["source_commit_sha"] != exact_commit
        or fleet["block_path"] != expected_block_path
        or fleet["complete"] is not True
        or not isinstance(expected_nodes, list)
        or not expected_nodes
        or expected_nodes != sorted(set(expected_nodes))
        or any(not isinstance(node, str) or ID.fullmatch(node) is None for node in expected_nodes)
    ):
        raise ValueError("Qualification final Fleet binding differs")
    require_digest(
        fleet["fleet_verification_receipt_sha256"],
        "Qualification final Fleet verifier receipt",
    )
    for field in (
        "desired_runtime_count", "current_runtime_observation_count",
        "active_guard_count", "residue_count",
    ):
        zero(fleet[field], f"Qualification final Fleet {field}")
    fleet_evaluated_at = positive_integer(
        fleet["evaluated_at_unix_ms"], "Qualification final Fleet time"
    )

    require_fields(
        final_state,
        {"version", "revision", "mode", "binding", "last_command_id", "updated_at_unix_ms"},
        "Qualification final admission state",
    )
    state_binding = require_fields(
        final_state["binding"], {"kind", "binding"}, "Qualification final state binding"
    )
    binding_fields = {
        "qualification_id", "deployment_id", "release_id", "source_commit_sha",
        "control_schema_version", "source_manifest_sha256", "source_bundle_sha256",
        "build_receipt_sha256", "release_manifest_sha256", "worker_bundle_sha256",
        "qualification_catalog_sha256", "qualification_cell_manifest_sha256",
        "aws_partition", "aws_account_id", "aws_region", "cell_id", "cell_namespace",
        "cats_account_id", "workspace_id", "allowed_mutation_classes",
        "qualification_expires_at_unix_ms",
    }
    binding = require_fields(
        state_binding["binding"], binding_fields, "Qualification final binding"
    )
    if (
        type(final_state["version"]) is not int
        or final_state["version"] != 1
        or final_state["mode"] != "closed"
        or final_state["revision"] != terminal["final_closed_revision"]
        or final_state["last_command_id"] != terminal["close_command_id"]
        or state_binding["kind"] != "qualification"
        or sha(compact(state_binding)) != begin["binding_sha256"]
        or binding["qualification_id"] != run_id
        or binding["workspace_id"] != workspace_id
        or binding["release_id"] != begin["release_id"]
        or binding["source_commit_sha"] != exact_commit
        or binding["control_schema_version"] != CONTROL_SCHEMA_VERSION
        or binding["release_manifest_sha256"] != release_sha256
        or binding["worker_bundle_sha256"] != worker_bundle_sha256
        or binding["qualification_catalog_sha256"] != qualification_catalog_sha256
        or binding["allowed_mutation_classes"] != QUALIFICATION_MUTATION_CLASSES
        or binding["qualification_expires_at_unix_ms"]
        != begin["qualification_expires_at_unix_ms"]
    ):
        raise ValueError("Qualification final Closed state binding differs")
    for field in (
        "source_manifest_sha256", "source_bundle_sha256", "build_receipt_sha256",
        "release_manifest_sha256", "worker_bundle_sha256",
        "qualification_catalog_sha256", "qualification_cell_manifest_sha256",
    ):
        require_digest(binding[field], f"Qualification binding {field}")
    state_updated_at = positive_integer(
        final_state["updated_at_unix_ms"], "Qualification final state update time"
    )
    if not (
        state_updated_at <= product_evaluated_at
        and product_evaluated_at <= cleanup_evaluated_at
        and product_evaluated_at <= fleet_evaluated_at
        and completed_at == max(cleanup_evaluated_at, fleet_evaluated_at)
    ):
        raise ValueError("Qualification Closed evidence order differs")
# QUALIFICATION_CLOSED_SUPPORT_END


def verify_run(raw_dir, expected_block_path):
    directory = safe_dir(raw_dir, f"{expected_block_path} qualification directory")
    validate_exact_run_file_names([entry.name for entry in directory.iterdir()])
    for name in EXPECTED_RUN_FILES:
        maximum = (
            1_048_576
            if name in QUALIFICATION_SUPPORT_FILES
            else 32 * 1_048_576
        )
        safe_path(str(directory / name), f"qualification {name}", {0o600}, maximum)
    checksums = (directory / "SHA256SUMS").read_text(encoding="ascii")
    expected_lines = []
    for name in CHECKSUM_FILES:
        value = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        expected_lines.append(f"{value}  {name}\n")
    if checksums != "".join(expected_lines):
        raise ValueError("qualification SHA256SUMS is not exact")
    if (directory / "exit-code").read_bytes() != b"0\n":
        raise ValueError("qualification exit code is not success")
    if (directory / "qualification-catalog.v1.json").read_bytes() != catalog_raw:
        raise ValueError("qualification used a different catalog")

    manifest, manifest_raw = load_json(directory / "manifest.json", "qualification manifest", canonical="compact")
    if manifest.get("version") != 1 or manifest.get("state") != "passed" or manifest.get("exit_code") != 0:
        raise ValueError("qualification manifest is not passed")
    if manifest.get("exact_commit") != exact_commit or manifest.get("block_path") != expected_block_path:
        raise ValueError("qualification manifest release or block path differs")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise ValueError("qualification run ID is not canonical")
    if manifest.get("schema_version") != CONTROL_SCHEMA_VERSION:
        raise ValueError(
            f"qualification did not run exact schema v{CONTROL_SCHEMA_VERSION}"
        )
    if manifest.get("qualification_catalog", {}).get("sha256") != qualification_catalog_sha256:
        raise ValueError("qualification manifest catalog digest differs")
    if manifest.get("qualification_catalog", {}).get("size_bytes") != len(catalog_raw):
        raise ValueError("qualification manifest catalog size differs")
    approved_release_hex = release_sha256.removeprefix("sha256:")
    if manifest.get("release_manifest", {}).get("sha256") != approved_release_hex or manifest.get(
        "release_manifest", {}
    ).get("approved_sha256") != approved_release_hex:
        raise ValueError("qualification manifest release digest differs")
    if manifest.get("installer_receipt", {}).get("sha256") != hashlib.sha256(installer_raw).hexdigest():
        raise ValueError("qualification manifest installer digest differs")
    if manifest.get("installer_receipt", {}).get("worker_bundle_sha256") != worker_bundle_sha256:
        raise ValueError("qualification manifest worker bundle differs")
    if manifest.get("qualification", {}).get("control_origin") != control_origin:
        raise ValueError("qualification control origin differs")
    workspace_id = manifest.get("qualification", {}).get("workspace_id")
    if not isinstance(workspace_id, str) or ID.fullmatch(workspace_id) is None:
        raise ValueError("qualification workspace ID is not canonical")
    configs = manifest.get("configs")
    if not isinstance(configs, list):
        raise ValueError("qualification config inventory is absent")
    target_configs = [item for item in configs if isinstance(item, dict) and item.get("label") == "usage-terminal-targets"]
    if len(target_configs) != 1 or target_configs[0].get("sha256") != targets_sha256.removeprefix("sha256:"):
        raise ValueError("qualification target descriptor digest differs")
    if target_configs[0].get("size_bytes") != len(targets_raw):
        raise ValueError("qualification target descriptor size differs")

    validate_qualification_closed_support(
        directory,
        manifest,
        run_id,
        workspace_id,
        expected_block_path,
    )

    evidence, evidence_raw = load_json_lines(directory / "case-evidence.jsonl", "case evidence")
    if manifest.get("case_evidence") != {"count": len(evidence), "sha256": sha(evidence_raw)}:
        raise ValueError("qualification manifest case-evidence binding differs")
    for row in evidence:
        if set(row) != {"case_id", "content", "filename", "kind", "sha256", "size_bytes"}:
            raise ValueError("case evidence wrapper has a foreign shape")
        if row["kind"] == "json":
            payload = compact(row["content"], ascii_only=True) + b"\n"
        elif row["kind"] == "text" and isinstance(row["content"], str):
            payload = row["content"].encode("utf-8")
        else:
            raise ValueError("case evidence kind is foreign")
        if row["sha256"] != sha(payload) or row["size_bytes"] != len(payload):
            raise ValueError("case evidence payload digest differs")

    framework_evidence = catalog["framework_required_evidence"]
    expected_scenarios = []
    expected_case_ids = []
    for case in catalog["cases"]:
        expected_case_ids.append(case["case_id"])
        required = case["required_evidence"] + framework_evidence
        expected_scenarios.append({**case, "required_evidence": required})
        actual = [
            (row["filename"], row["kind"])
            for row in evidence
            if row["case_id"] == case["case_id"]
        ]
        expected = [(item["filename"], item["kind"]) for item in required]
        if sorted(actual) != sorted(expected) or len(actual) != len(expected):
            raise ValueError("qualification case evidence is not the catalog exact set")
    if manifest.get("scenarios") != expected_scenarios:
        raise ValueError("qualification manifest scenario catalog differs")

    aggregates = [
        row for row in evidence
        if row["case_id"] == SOURCE_CASE and row["filename"] == "usage-source-terminal-receipts.json"
    ]
    lives = [
        row for row in evidence
        if row["case_id"] == SOURCE_CASE and row["filename"] == "usage-live-delivery-receipt.json"
    ]
    if len(aggregates) != 1 or len(lives) != 1:
        raise ValueError("qualification has no unique Usage source evidence pair")
    aggregate = aggregates[0]["content"]
    expected_aggregate_keys = {
        "block_path", "cat_id", "kind", "qualification_catalog_sha256", "release_commit",
        "run_id", "run_window_from_unix_ms", "run_window_to_unix_ms", "source_set_sha256",
        "sources", "version", "worker_bundle_sha256", "workspace_id",
    }
    if not isinstance(aggregate, dict) or set(aggregate) != expected_aggregate_keys:
        raise ValueError("Usage source aggregate has a foreign shape")
    if aggregate["kind"] != "cats.usage-source-terminal-receipts.v1" or aggregate["version"] != 1:
        raise ValueError("Usage source aggregate version is foreign")
    if (
        aggregate["block_path"] != expected_block_path
        or aggregate["run_id"] != run_id
        or aggregate["release_commit"] != exact_commit
        or aggregate["qualification_catalog_sha256"] != qualification_catalog_sha256
        or aggregate["worker_bundle_sha256"] != worker_bundle_sha256
        or aggregate["workspace_id"] != workspace_id
    ):
        raise ValueError("Usage source aggregate binding differs")
    cat_id = aggregate["cat_id"]
    if not isinstance(cat_id, str) or ID.fullmatch(cat_id) is None:
        raise ValueError("Usage source aggregate Cat ID is invalid")
    started = manifest.get("started_at_unix_seconds")
    ended = manifest.get("ended_at_unix_seconds")
    from_ms = aggregate["run_window_from_unix_ms"]
    to_ms = aggregate["run_window_to_unix_ms"]
    if not all(type(item) is int and item >= 0 for item in (started, ended, from_ms, to_ms)):
        raise ValueError("Usage run window is invalid")
    if from_ms != started * 1000 or to_ms < from_ms or to_ms > (ended + 61) * 1000:
        raise ValueError("Usage source evidence is outside the exact run window")
    sources = aggregate["sources"]
    if not isinstance(sources, list) or not sources:
        raise ValueError("Usage source aggregate is empty")
    previous = None
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"receipt_sha256", "source_epoch", "source_id"}:
            raise ValueError("Usage source expectation has a foreign shape")
        key = (source["source_id"], source["source_epoch"])
        if (
            not isinstance(key[0], str)
            or not 1 <= len(key[0]) <= 256
            or not key[0].startswith("node/")
            or not key[0].endswith("/cat/" + cat_id)
            or any(not 0x20 <= ord(value) <= 0x7E for value in key[0])
            or not isinstance(key[1], str)
            or not 1 <= len(key[1]) <= 512
            or any(not 0x20 <= ord(value) <= 0x7E for value in key[1])
            or not isinstance(source["receipt_sha256"], str)
            or DIGEST.fullmatch(source["receipt_sha256"]) is None
            or (previous is not None and previous >= key)
        ):
            raise ValueError("Usage source expectation is not strictly canonical")
        previous = key
    if aggregate["source_set_sha256"] != typed_source_set_sha256(sources):
        raise ValueError("Usage per-path source-set digest differs")

    live = lives[0]["content"]
    expected_live_keys = {
        "cat_id", "durable_spool_on_delivery_path", "end_sequence",
        "exact_current_agent_binding_required", "interval_end_unix_ms", "metrics", "proof",
        "run_id", "run_window_from_unix_ms", "run_window_to_unix_ms", "source_epoch",
        "source_id", "source_terminal_receipt_proved", "source_terminal_receipt_sha256",
        "spool_absence_used_as_authority", "version", "workspace_id",
    }
    if not isinstance(live, dict) or set(live) != expected_live_keys:
        raise ValueError("Usage live receipt has a foreign shape")
    if (
        live["version"] != 1
        or live["proof"] != "sampler_spool_signed_ingest_projection"
        or live["run_id"] != run_id
        or live["workspace_id"] != workspace_id
        or live["cat_id"] != cat_id
        or live["run_window_from_unix_ms"] != from_ms
        or live["run_window_to_unix_ms"] != to_ms
        or live["durable_spool_on_delivery_path"] is not True
        or live["exact_current_agent_binding_required"] is not True
        or live["spool_absence_used_as_authority"] is not False
        or live["source_terminal_receipt_proved"] is not True
    ):
        raise ValueError("Usage live receipt binding differs")
    live_matches = [
        source for source in sources
        if source["source_id"] == live["source_id"] and source["source_epoch"] == live["source_epoch"]
    ]
    if len(live_matches) != 1 or live_matches[0]["receipt_sha256"] != live["source_terminal_receipt_sha256"]:
        raise ValueError("Usage live receipt is outside its terminal source set")
    metrics = live["metrics"]
    if (
        not isinstance(metrics, list)
        or len(metrics) != 2
        or any(
            not isinstance(item, dict)
            or set(item) != {"metric", "quantity", "unit"}
            or not isinstance(item["quantity"], str)
            or re.fullmatch(r"0|[1-9][0-9]*", item["quantity"]) is None
            or not isinstance(item["unit"], str)
            or not item["unit"]
            for item in metrics
        )
        or sorted(item["metric"] for item in metrics) != ["cpu_usec", "memory_byte_millis"]
        or type(live["end_sequence"]) is not int
        or live["end_sequence"] < 0
        or type(live["interval_end_unix_ms"]) is not int
        or live["interval_end_unix_ms"] < from_ms
        or live["interval_end_unix_ms"] > to_ms
    ):
        raise ValueError("Usage live receipt does not contain one complete meter pair")
    if not any(item["quantity"] != "0" for item in metrics):
        raise ValueError("Usage live receipt is not nonzero")

    results, _ = load_json_lines(directory / "scenario-results.jsonl", "scenario results")
    if [row.get("case_id") for row in results] != expected_case_ids or any(
        row.get("status") != "passed"
        or row.get("run_exit_code") != 0
        or row.get("cleanup_exit_code") != 0
        or row.get("evidence_exit_code") != 0
        for row in results
    ):
        raise ValueError("qualification scenario results are not the catalog all-pass sequence")
    source_results = [row for row in results if row.get("case_id") == SOURCE_CASE]
    if len(source_results) != 1 or source_results[0].get("status") != "passed":
        raise ValueError("Usage source-terminal case did not pass")
    return {
        "block_path": expected_block_path,
        "case_evidence_sha256": sha(evidence_raw),
        "qualification_manifest_sha256": sha(manifest_raw),
        "run_id": run_id,
        "source_terminal_set_sha256": aggregate["source_set_sha256"],
        "sources": sources,
        "workspace_id": workspace_id,
    }


kernel = verify_run(kernel_dir_raw, "kernel-nbd")
vhost = verify_run(vhost_dir_raw, "vhost-user")
if Path(kernel_dir_raw) == Path(vhost_dir_raw) or kernel["run_id"] == vhost["run_id"]:
    raise ValueError("the two block-path qualifications are not distinct")
kernel_workspace_id = kernel.pop("workspace_id")
vhost_workspace_id = vhost.pop("workspace_id")
if kernel_workspace_id != vhost_workspace_id:
    raise ValueError("the two block-path qualifications used different workspaces")

by_key = {}
for run in (kernel, vhost):
    for source in run.pop("sources"):
        key = (source["source_id"], source["source_epoch"])
        existing = by_key.get(key)
        if existing is not None and existing != source:
            raise ValueError("the two runs disagree on one Usage source receipt")
        by_key[key] = source
sources = [by_key[key] for key in sorted(by_key)]
source_set_sha256 = typed_source_set_sha256(sources)

frames = [
    "cats.usage-target-terminal-epoch.v1",
    kernel["qualification_manifest_sha256"],
    vhost["qualification_manifest_sha256"],
    targets_sha256,
    source_set_sha256,
]
epoch = hashlib.sha256()
for frame in frames:
    encoded = frame.encode("utf-8")
    epoch.update(len(encoded).to_bytes(8, "big"))
    epoch.update(encoded)
terminal_epoch_id = epoch.hexdigest()[:32]
if terminal_epoch_id == "0" * 32:
    raise ValueError("derived terminal epoch is all-zero")

result = {
    "block_runs": [kernel, vhost],
    "curl_path": curl_path,
    "expected_targets_file_sha256": targets_sha256,
    "qualification_catalog_sha256": qualification_catalog_sha256,
    "source_set_sha256": source_set_sha256,
    "sources": sources,
    "target_binding_sha256": target_binding_sha256,
    "terminal_epoch_id": terminal_epoch_id,
    "timeout_path": timeout_path,
    "verifier_path": verifier_path,
    "verifier_sha256": verifier_sha256,
    "worker_bundle_sha256": worker_bundle_sha256,
}
sys.stdout.buffer.write(compact(result) + b"\n")
PY
then
  fail "release or two-path qualification preflight failed closed"
fi
chmod 0600 "$preflight"

publish_exact() {
  local source=$1 destination=$2 mode=$3
  python3 - "$source" "$destination" "$mode" <<'PY'
import os
from pathlib import Path
import stat
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
mode = int(sys.argv[3], 8)
expected = source.read_bytes()
if not expected or len(expected) > 32 * 1024 * 1024:
    raise SystemExit(1)
parent = destination.parent
parent_stat = os.lstat(parent)
if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != 0 or parent_stat.st_gid != 0:
    raise SystemExit(1)
if stat.S_IMODE(parent_stat.st_mode) != 0o700:
    raise SystemExit(1)


def inspect(path, links):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        value = b""
        while len(value) <= 32 * 1024 * 1024:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            value += chunk
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (
        identity(before) != identity(after)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != 0
        or before.st_nlink not in links
        or stat.S_IMODE(before.st_mode) != mode
        or value != expected
    ):
        raise SystemExit(1)
    return before


pending = parent / ("." + destination.name + ".pending")
if destination.exists():
    final = inspect(destination, {1, 2})
    if pending.exists():
        staged = inspect(pending, {1, 2})
        if (final.st_dev, final.st_ino) != (staged.st_dev, staged.st_ino):
            raise SystemExit(1)
        os.unlink(pending)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        os.fsync(directory)
        os.close(directory)
    raise SystemExit(0)

if not pending.exists():
    descriptor = os.open(
        pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(expected):
            offset += os.write(descriptor, expected[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
else:
    inspect(pending, {1})
directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
os.fsync(directory)
try:
    os.link(pending, destination, follow_symlinks=False)
except FileExistsError:
    final = inspect(destination, {1, 2})
    staged = inspect(pending, {1, 2})
    if (final.st_dev, final.st_ino) != (staged.st_dev, staged.st_ino):
        raise SystemExit(1)
os.fsync(directory)
os.unlink(pending)
os.fsync(directory)
os.close(directory)
inspect(destination, {1})
PY
}

publish_exact "$qualification_catalog" "$output_dir/qualification-catalog.v1.json" 0600 || \
  fail "qualification catalog no-replace publication failed"
publish_exact "$usage_terminal_targets" "$output_dir/usage-terminal-targets.json" 0600 || \
  fail "Usage target descriptor no-replace publication failed"
[[ sha256:$(sha256sum "$output_dir/qualification-catalog.v1.json" | awk '{print $1}') == \
  "$(jq -er '.qualification_catalog_sha256' "$preflight")" ]] || \
  fail "published qualification catalog digest differs from preflight"
[[ sha256:$(sha256sum "$output_dir/usage-terminal-targets.json" | awk '{print $1}') == \
  "$(jq -er '.expected_targets_file_sha256' "$preflight")" ]] || \
  fail "published Usage target descriptor digest differs from preflight"

sources_json=$(jq -c '.sources' "$preflight")
source_set_sha256=$(jq -er '.source_set_sha256' "$preflight")
terminal_epoch_id=$(jq -er '.terminal_epoch_id' "$preflight")
worker_bundle_sha256=$(jq -er '.worker_bundle_sha256' "$preflight")
worker_bundle_hex=${worker_bundle_sha256#sha256:}
request=$output_dir/usage-target-terminal-request.json
request_candidate=$private_stage/usage-target-terminal-request.json
if [[ -e $request ]]; then
  [[ -f $request && ! -L $request && $(stat -c '%a:%u:%g:%h' "$request") == 400:0:0:1 ]] || \
    fail "existing target request journal violates its immutable file contract"
  created_at_unix_ms=$(jq -er '.created_at_unix_ms | select(type == "number" and . >= 0 and floor == .)' "$request") || \
    fail "existing target request journal has an invalid creation time"
else
  created_at_unix_ms=$(( $(date +%s) * 1000 ))
fi
jq -S -c -n \
  --slurpfile targets "$output_dir/usage-terminal-targets.json" \
  --arg artifact_sha256 "$worker_bundle_hex" \
  --argjson created_at_unix_ms "$created_at_unix_ms" \
  --arg release_commit "$exact_commit" \
  --arg source_set_sha256 "$source_set_sha256" \
  --argjson sources "$sources_json" \
  --arg terminal_epoch_id "$terminal_epoch_id" '
  {artifact_sha256:$artifact_sha256,contract_version:1,
   created_at_unix_ms:$created_at_unix_ms,fresh_target:$targets[0].fresh_target,
   old_target:$targets[0].old_target,release_commit:$release_commit,
   shards:$targets[0].shards,source_set_sha256:$source_set_sha256,
   sources:$sources,terminal_epoch_id:$terminal_epoch_id}' >"$request_candidate"
chmod 0400 "$request_candidate"
publish_exact "$request_candidate" "$request" 0400 || \
  fail "target request journal conflicts with this exact two-path source union"

curl_bin=$(jq -er '.curl_path' "$preflight")
timeout_bin=$(jq -er '.timeout_path' "$preflight")
verifier_bin=$(jq -er '.verifier_path' "$preflight")
auth_header=$private_stage/authorization.header
token=$(<"$token_file")
token=${token%$'\n'}
[[ -n $token && $token != *$'\n'* && $token != *$'\r'* ]] || fail "control token changed after preflight"
printf 'authorization: Bearer %s\n' "$token" >"$auth_header"
unset token
chmod 0600 "$auth_header"

HTTP_STATUS=
curl_json() {
  local method=$1 url=$2 destination=$3 expected_status=$4
  shift 4
  local headers status curl_status content_types encodings size
  headers=$private_stage/response-headers
  : >"$headers"
  set +e
  status=$(env -i "$curl_bin" --disable --silent --show-error \
    --proto '=https' --tlsv1.2 --max-time 30 --max-filesize 1048576 \
    --request "$method" --header "@$auth_header" --header 'accept: application/json' \
    --header 'accept-encoding: identity' --dump-header "$headers" \
    --write-out '%{http_code}' "$@" --output "$destination" "$url")
  curl_status=$?
  set -e
  if [[ $curl_status -ne 0 ]]; then
    HTTP_STATUS=
    rm -f "$destination" "$headers"
    return 75
  fi
  [[ $status =~ ^[0-9]{3}$ ]] || fail "$method returned an invalid HTTP status"
  case ",$expected_status," in *",$status,"*) ;; *) fail "$method returned HTTP $status" ;; esac
  size=$(wc -c <"$destination")
  [[ $size -le 1048576 ]] || fail "$method response exceeds the byte bound"
  content_types=$(awk 'BEGIN{IGNORECASE=1} /^Content-Type:/{sub(/\r$/,""); sub(/[[:space:]]+$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$headers")
  encodings=$(awk 'BEGIN{IGNORECASE=1} /^Content-Encoding:/{sub(/\r$/,""); sub(/[[:space:]]+$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$headers")
  rm -f "$headers"
  [[ $content_types == application/json ]] || fail "$method response Content-Type is not exact"
  [[ -z $encodings || $encodings == identity ]] || fail "$method response encoding is foreign"
  jq -e . "$destination" >/dev/null || fail "$method response is not JSON"
  HTTP_STATUS=$status
}

begin_response=$private_stage/target-begin.json
begin_status=75
for _ in 1 2; do
  set +e
  curl_json POST "$control_origin/v1/admin/usage/target-terminal/begin" \
    "$begin_response" 200 --header 'content-type: application/json' --data-binary "@$request"
  begin_status=$?
  set -e
  [[ $begin_status -eq 75 ]] || break
done
[[ $begin_status -eq 0 ]] || fail "target begin remained ambiguous after exact journal replay"
request_sha256=$(jq -er '
  select(keys == ["request_sha256","state"]
    and (.state == "prepared" or .state == "exact_replay")
    and (.request_sha256 | test("^sha256:[0-9a-f]{64}$"))) | .request_sha256' \
  "$begin_response") || fail "target begin response is not exact"

complete_response=$private_stage/target-complete.json
terminal=false
complete_attempt=0
while [[ $complete_attempt -lt 120 ]]; do
  complete_attempt=$((complete_attempt + 1))
  set +e
  curl_json POST "$control_origin/v1/admin/usage/target-terminal/complete" \
    "$complete_response" 200,202 --header 'content-type: application/json' --data-binary "@$request"
  complete_status=$?
  set -e
  if [[ $complete_status -eq 75 ]]; then
    sleep 2
    continue
  fi
  [[ $complete_status -eq 0 ]] || fail "target completion discovery failed"
  if [[ $HTTP_STATUS == 202 ]]; then
    jq -e --arg request_sha256 "$request_sha256" '
      keys == ["receipt","request_sha256","state"] and .state == "pending"
      and .request_sha256 == $request_sha256 and .receipt == null' \
      "$complete_response" >/dev/null || fail "pending target response is foreign"
    sleep 2
    continue
  fi
  if [[ $HTTP_STATUS == 200 ]] && jq -e --arg request_sha256 "$request_sha256" '
    keys == ["receipt","request_sha256","state"] and .state == "terminal"
    and .request_sha256 == $request_sha256 and (.receipt | type == "object")' \
    "$complete_response" >/dev/null; then
    terminal=true
    break
  fi
  fail "target completion returned a foreign outcome"
done
[[ $terminal == true ]] || fail "target barriers did not converge before the bounded deadline"

target_candidate=$private_stage/usage-target-terminal-receipt.json
jq -S -c '.receipt' "$complete_response" >"$target_candidate"
chmod 0600 "$target_candidate"
publish_exact "$target_candidate" "$output_dir/usage-target-terminal-receipt.json" 0600 || \
  fail "target receipt conflicts with an earlier discovery"

verification_receipt=$output_dir/usage-target-terminal-verification.receipt.json
if ! env -i "$timeout_bin" --signal=TERM --kill-after=5 30 \
  "$verifier_bin" \
  --receipt-file "$output_dir/usage-target-terminal-receipt.json" \
  --expected-request-file "$request" \
  --expected-targets-file "$output_dir/usage-terminal-targets.json" \
  --expected-targets-sha256 "$usage_terminal_targets_sha256" \
  --release-commit "$exact_commit" \
  --worker-bundle-sha256 "$worker_bundle_sha256" \
  --receipt-out "$verification_receipt" >"$private_stage/verifier.log" 2>&1; then
  fail "release-bound Rust target receipt verification failed"
fi

request_file_sha256=sha256:$(sha256sum "$request" | awk '{print $1}')
target_receipt_file_sha256=sha256:$(sha256sum "$output_dir/usage-target-terminal-receipt.json" | awk '{print $1}')
targets_file_sha256=sha256:$(sha256sum "$output_dir/usage-terminal-targets.json" | awk '{print $1}')
verifier_sha256=$(jq -er '.verifier_sha256' "$preflight")
target_binding_sha256=$(jq -er '.target_binding_sha256' "$preflight")
jq -e \
  --arg binary_sha256 "$verifier_sha256" \
  --arg expected_request_file_sha256 "$request_file_sha256" \
  --arg expected_targets_file_sha256 "$targets_file_sha256" \
  --arg release_commit "$exact_commit" \
  --arg target_binding_sha256 "$target_binding_sha256" \
  --arg target_receipt_file_sha256 "$target_receipt_file_sha256" \
  --arg target_request_sha256 "$request_sha256" \
  --arg worker_bundle_sha256 "$worker_bundle_sha256" '
  keys == ["binary_sha256","expected_request_file_sha256","expected_targets_file_sha256",
    "kind","release_commit","target_binding_sha256","target_receipt_file_sha256",
    "target_request_sha256","validated","version","worker_bundle_sha256"]
  and .binary_sha256 == $binary_sha256
  and .expected_request_file_sha256 == $expected_request_file_sha256
  and .expected_targets_file_sha256 == $expected_targets_file_sha256
  and .kind == "cats.usage-terminal-receipt-verification.v1"
  and .release_commit == $release_commit
  and .target_binding_sha256 == $target_binding_sha256
  and .target_receipt_file_sha256 == $target_receipt_file_sha256
  and .target_request_sha256 == $target_request_sha256
  and .validated == true and .version == 1
  and .worker_bundle_sha256 == $worker_bundle_sha256' "$verification_receipt" >/dev/null || \
  fail "Rust verification receipt projection is foreign"

verification_file_sha256=sha256:$(sha256sum "$verification_receipt" | awk '{print $1}')
global_manifest=$output_dir/usage-global-terminal-finalization.manifest.json
if [[ -e $global_manifest ]]; then
  [[ -f $global_manifest && ! -L $global_manifest && \
    $(stat -c '%a:%u:%g:%h' "$global_manifest") == 600:0:0:1 ]] || \
    fail "existing global manifest violates its immutable file contract"
  completed_at_unix_ms=$(jq -er '.completed_at_unix_ms | select(type == "number" and . >= 0 and floor == .)' \
    "$global_manifest") || fail "existing global manifest completion time is invalid"
else
  completed_at_unix_ms=$(( $(date +%s) * 1000 ))
fi
global_manifest_candidate=$private_stage/usage-global-terminal-finalization.manifest.json
jq -S -c -n \
  --argjson block_runs "$(jq -c '.block_runs' "$preflight")" \
  --argjson completed_at_unix_ms "$completed_at_unix_ms" \
  --arg expected_targets_file_sha256 "$targets_file_sha256" \
  --arg qualification_catalog_sha256 "$(jq -er '.qualification_catalog_sha256' "$preflight")" \
  --arg release_commit "$exact_commit" \
  --arg source_set_sha256 "$source_set_sha256" \
  --argjson sources "$sources_json" \
  --arg target_binding_sha256 "$target_binding_sha256" \
  --arg target_receipt_file_sha256 "$target_receipt_file_sha256" \
  --arg target_request_file_sha256 "$request_file_sha256" \
  --arg target_request_sha256 "$request_sha256" \
  --arg target_verification_file_sha256 "$verification_file_sha256" \
  --arg terminal_epoch_id "$terminal_epoch_id" \
  --arg worker_bundle_sha256 "$worker_bundle_sha256" '
  {block_runs:$block_runs,completed_at_unix_ms:$completed_at_unix_ms,
   expected_targets_file_sha256:$expected_targets_file_sha256,
   kind:"cats.usage-global-terminal-finalization.v1",outcome:"terminal",
   qualification_catalog_sha256:$qualification_catalog_sha256,
   release_commit:$release_commit,source_set_sha256:$source_set_sha256,sources:$sources,
   target_binding_sha256:$target_binding_sha256,
   target_receipt_file_sha256:$target_receipt_file_sha256,
   target_request_file_sha256:$target_request_file_sha256,
   target_request_sha256:$target_request_sha256,
   target_verification_file_sha256:$target_verification_file_sha256,
   terminal_epoch_id:$terminal_epoch_id,version:1,
   worker_bundle_sha256:$worker_bundle_sha256}' >"$global_manifest_candidate"
chmod 0600 "$global_manifest_candidate"
publish_exact "$global_manifest_candidate" "$global_manifest" 0600 || \
  fail "global terminal manifest conflicts with an earlier finalization"

case_evidence_candidate=$private_stage/case-evidence.jsonl
: >"$case_evidence_candidate"
for evidence_name in \
  usage-target-terminal-request.json \
  usage-target-terminal-receipt.json \
  usage-target-terminal-verification.receipt.json; do
  evidence_path=$output_dir/$evidence_name
  evidence_sha256=sha256:$(sha256sum "$evidence_path" | awk '{print $1}')
  evidence_size=$(wc -c <"$evidence_path" | tr -d ' ')
  jq -S -c -n \
    --arg case_id usage-target-terminal-receipt \
    --arg filename "$evidence_name" --arg kind json \
    --arg sha256 "$evidence_sha256" --argjson size_bytes "$evidence_size" \
    --slurpfile content "$evidence_path" '
    {case_id:$case_id,content:$content[0],filename:$filename,kind:$kind,
     sha256:$sha256,size_bytes:$size_bytes}' >>"$case_evidence_candidate"
done
chmod 0600 "$case_evidence_candidate"
publish_exact "$case_evidence_candidate" "$output_dir/case-evidence.jsonl" 0600 || \
  fail "global case evidence conflicts with an earlier finalization"

checksums_candidate=$private_stage/SHA256SUMS
(
  cd "$output_dir"
  LC_ALL=C sha256sum \
    case-evidence.jsonl \
    qualification-catalog.v1.json \
    usage-global-terminal-finalization.manifest.json \
    usage-target-terminal-receipt.json \
    usage-target-terminal-request.json \
    usage-target-terminal-verification.receipt.json \
    usage-terminal-targets.json
) >"$checksums_candidate"
chmod 0600 "$checksums_candidate"
publish_exact "$checksums_candidate" "$output_dir/SHA256SUMS" 0600 || \
  fail "global checksum inventory conflicts with an earlier finalization"

python3 - "$output_dir" <<'PY' || fail "global output is not the exact 7-file evidence set plus SHA256SUMS"
from pathlib import Path
import os
import stat
import sys

directory = Path(sys.argv[1])
expected = {
    "SHA256SUMS",
    "case-evidence.jsonl",
    "qualification-catalog.v1.json",
    "usage-global-terminal-finalization.manifest.json",
    "usage-target-terminal-receipt.json",
    "usage-target-terminal-request.json",
    "usage-target-terminal-verification.receipt.json",
    "usage-terminal-targets.json",
}
if {entry.name for entry in directory.iterdir()} != expected:
    raise SystemExit(1)
for name in expected:
    metadata = os.lstat(directory / name)
    expected_mode = 0o400 if name == "usage-target-terminal-request.json" else 0o600
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise SystemExit(1)
PY

printf 'USAGE_TARGET_TERMINAL_RECEIPT terminal_epoch_id=%s request_sha256=%s\n' \
  "$terminal_epoch_id" "$request_sha256"
