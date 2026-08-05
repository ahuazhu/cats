#!/usr/bin/env bash
set -Eeuo pipefail

# Issue #124: drive one lifecycle generation while the guarded production HA
# workflow replaces the elected cats-controld reconciler. This harness never
# calls kubectl: the only permitted leader deletion is the reviewed workflow's
# UID-checked deletion after its redundancy and PDB checks.

CATS_BIN="${CATS_BIN:-./target/debug/cats}"
WORKSPACE="${CATS_TEST_WORKSPACE:-default/qual-124-20260805}"
WORKSPACE_ID="${CATS_SUT_WORKSPACE_ID:-}"
SUT_RELEASE_SHA="${CATS_SUT_RELEASE_SHA:-}"
SUT_DEPLOY_RUN_ID="${CATS_SUT_DEPLOY_RUN_ID:-}"
SUT_API_ORIGIN="${CATS_SUT_API_ORIGIN:-https://cats.run}"
HA_WORKFLOW="${CATS_HA_WORKFLOW:-verify-control-plane-ha.yml}"
GITHUB_REPOSITORY="${CATS_GITHUB_REPOSITORY:-ahuazhu/cats}"
EXECUTE_CONFIRMATION="${CATS_HA_EXECUTE:-}"
ROUNDS="${CATS_HA_ROUNDS:-3}"
DURABILITIES="${CATS_HA_DURABILITIES:-strict relaxed}"
SCENARIOS="${CATS_HA_SCENARIOS:-start resume restore suspend warm stop}"
RUN_ID="${CATS_RUN_ID:-$(date -u +%m%d%H%M%S)}"
RESULT_ROOT="${CATS_RESULT_ROOT:-test-results/qualification-20260805/raw/ha-handoff}"
RUN_DIR="${RESULT_ROOT}/${RUN_ID}"
OP_TIMEOUT_SECONDS="${CATS_OP_TIMEOUT_SECONDS:-600}"
WORKFLOW_TIMEOUT_SECONDS="${CATS_HA_WORKFLOW_TIMEOUT_SECONDS:-1200}"
TRANSITION_TIMEOUT_SECONDS="${CATS_HA_TRANSITION_TIMEOUT_SECONDS:-20}"
WATERMARK_TIMEOUT_SECONDS="${CATS_HA_WATERMARK_TIMEOUT_SECONDS:-30}"
ROUTE_TIMEOUT_SECONDS="${CATS_HA_ROUTE_TIMEOUT_SECONDS:-120}"
WATERMARK_PROBE_CMD="${CATS_WATERMARK_PROBE_CMD:-}"
REQUIRED_NODE_ID="${CATS_HA_REQUIRED_NODE_ID:-}"
ADMIN_NODE_HOOK="${CATS_HA_ADMIN_NODE_HOOK:-}"
ADMIN_NODE_HOOK_REPO_PATH="${CATS_HA_ADMIN_NODE_HOOK_REPO_PATH:-}"
WINDOW_NONCE="${CATS_HA_WINDOW_NONCE:-}"

MODE="live"
if [[ "${1:-}" == "--dry-run" ]]; then
  MODE="dry-run"
elif [[ "${1:-}" == "--validate-fixtures" ]]; then
  MODE="fixture"
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--dry-run|--validate-fixtures]" >&2
  exit 2
fi

die() {
  echo "$*" >&2
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

validate_positive_integer() {
  local name="$1" value="$2"
  case "${value}" in
    ''|*[!0-9]*) die "${name} must be a positive integer" ;;
  esac
  (( value >= 1 )) || die "${name} must be at least one"
}

validate_words() {
  local durability scenario
  for durability in ${DURABILITIES}; do
    case "${durability}" in
      strict|relaxed) ;;
      *) die "unsupported durability: ${durability}" ;;
    esac
  done
  [[ -n "${DURABILITIES//[[:space:]]/}" ]] || die "CATS_HA_DURABILITIES is empty"
  for scenario in ${SCENARIOS}; do
    case "${scenario}" in
      start|resume|restore|suspend|warm|stop) ;;
      *) die "unsupported scenario: ${scenario}" ;;
    esac
  done
  [[ -n "${SCENARIOS//[[:space:]]/}" ]] || die "CATS_HA_SCENARIOS is empty"
}

validate_static() {
  validate_positive_integer CATS_HA_ROUNDS "${ROUNDS}"
  validate_positive_integer CATS_OP_TIMEOUT_SECONDS "${OP_TIMEOUT_SECONDS}"
  validate_positive_integer CATS_HA_WORKFLOW_TIMEOUT_SECONDS "${WORKFLOW_TIMEOUT_SECONDS}"
  validate_positive_integer CATS_HA_TRANSITION_TIMEOUT_SECONDS "${TRANSITION_TIMEOUT_SECONDS}"
  validate_positive_integer CATS_HA_WATERMARK_TIMEOUT_SECONDS "${WATERMARK_TIMEOUT_SECONDS}"
  validate_positive_integer CATS_HA_ROUTE_TIMEOUT_SECONDS "${ROUTE_TIMEOUT_SECONDS}"
  validate_words
  [[ "${RUN_ID}" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] ||
    die "CATS_RUN_ID must be 1-32 lowercase alphanumeric/hyphen characters"
  [[ "${SUT_API_ORIGIN}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] ||
    die "CATS_SUT_API_ORIGIN must be an HTTPS origin without credentials, path or query"
  if [[ -n "${REQUIRED_NODE_ID}" ]]; then
    [[ "${REQUIRED_NODE_ID}" =~ ^q124-[a-z0-9][a-z0-9-]{7,54}$ ]] ||
      die "CATS_HA_REQUIRED_NODE_ID must be one exact q124-* temporary Node ID"
  fi
}

validate_live_locator_scope() {
  [[ "${WORKSPACE_ID}" == "ws_788c5bfc3931" ]] ||
    die "CATS_SUT_WORKSPACE_ID must be exactly ws_788c5bfc3931"
  [[ "${WORKSPACE}" == "default/qual-124-20260805" ]] ||
    die "CATS_TEST_WORKSPACE must be exactly default/qual-124-20260805"
  [[ "${SUT_API_ORIGIN}" == "https://cats.run" ]] ||
    die "CATS_SUT_API_ORIGIN must be exactly https://cats.run"
  [[ "${HA_WORKFLOW}" == "verify-control-plane-ha.yml" ]] ||
    die "CATS_HA_WORKFLOW must be exactly verify-control-plane-ha.yml"
  [[ "${GITHUB_REPOSITORY}" == "ahuazhu/cats" ]] ||
    die "CATS_GITHUB_REPOSITORY must be exactly ahuazhu/cats"
}

file_uid_mode() {
  if stat -f '%u %Lp' "$1" >/dev/null 2>&1; then
    stat -f '%u %Lp' "$1"
  else
    stat -c '%u %a' "$1"
  fi
}

verify_admin_hook_provenance() {
  local expected_sha actual_sha owner mode
  [[ "${ADMIN_NODE_HOOK_REPO_PATH}" == \
      "deploy/aws/qualification/q124-admin-node-runner.sh" ]] ||
    die "CATS_HA_ADMIN_NODE_HOOK_REPO_PATH must name the reviewed independent-runner adapter"
  [[ "${ADMIN_NODE_HOOK}" =~ ^/[A-Za-z0-9._/-]+$ && "${ADMIN_NODE_HOOK}" != *".."* \
     && -f "${ADMIN_NODE_HOOK}" && ! -L "${ADMIN_NODE_HOOK}" && -x "${ADMIN_NODE_HOOK}" ]] ||
    die "runner admin hook must be one absolute executable regular file"
  read -r owner mode < <(file_uid_mode "${ADMIN_NODE_HOOK}")
  [[ "${owner}" == "${EUID}" && "${mode}" == "700" ]] ||
    die "runner admin hook must be owned by the harness user with mode 0700"
  git cat-file -e "${SUT_RELEASE_SHA}^{commit}" 2>/dev/null ||
    die "SUT release SHA is not locally reviewable"
  git cat-file -e "${SUT_RELEASE_SHA}:${ADMIN_NODE_HOOK_REPO_PATH}" 2>/dev/null ||
    die "reviewed admin hook is absent from the exact SUT release SHA"
  expected_sha="$(git show "${SUT_RELEASE_SHA}:${ADMIN_NODE_HOOK_REPO_PATH}" | shasum -a 256 | awk '{print $1}')"
  actual_sha="$(shasum -a 256 "${ADMIN_NODE_HOOK}" | awk '{print $1}')"
  [[ "${actual_sha}" == "${expected_sha}" ]] ||
    die "installed admin hook does not match the reviewed SUT release"
}

scenario_source() {
  case "$1" in
    start) printf 'cold\n' ;;
    resume) printf 'suspended\n' ;;
    restore) printf 'warm\n' ;;
    suspend|warm|stop) printf 'running\n' ;;
  esac
}

scenario_transition() {
  case "$1" in
    start|resume|restore) printf 'starting\n' ;;
    suspend) printf 'suspending\n' ;;
    warm) printf 'warming\n' ;;
    stop) printf 'stopping\n' ;;
  esac
}

scenario_target() {
  case "$1" in
    start|resume|restore) printf 'running\n' ;;
    suspend) printf 'suspended\n' ;;
    warm) printf 'warm\n' ;;
    stop) printf 'cold\n' ;;
  esac
}

scenario_operation_kind() {
  case "$1" in
    start) printf 'cat.start\n' ;;
    resume|restore) printf 'cat.resume\n' ;;
    suspend) printf 'cat.suspend\n' ;;
    warm) printf 'cat.warm\n' ;;
    stop) printf 'cat.stop\n' ;;
  esac
}

scenario_cli_action() {
  case "$1" in
    restore) printf 'resume\n' ;;
    start|resume|suspend|warm|stop) printf '%s\n' "$1" ;;
  esac
}

transition_matches() {
  local cat_file="$1" operation_file="$2" desired="$3" transitional="$4"
  jq -se --arg desired "${desired}" --arg transitional "${transitional}" '
    .[0] as $cat | .[1] as $operation
    | $cat.desired_state == $desired
      and $cat.observed_state == $transitional
      and ($cat.generation | type == "number")
      and ($operation.id | type == "string" and startswith("op_"))
      and $operation.resource_id == $cat.id
      and $operation.resource_generation == $cat.generation
      and ($operation.phase == "pending" or $operation.phase == "running")
  ' "${cat_file}" "${operation_file}" >/dev/null
}

watermark_is_relaxed_backlog() {
  jq -e '
    (.local_watermark | type == "number")
    and (.remote_watermark | type == "number")
    and .local_watermark > .remote_watermark
  ' "$1" >/dev/null
}

watermark_probe_matches_cat_node() {
  local file="$1" cat_id="$2" node_id="$3"
  jq -e --arg cat "${cat_id}" --arg node "${node_id}" '
    .cat_id == $cat and .node_id == $node
    and (.local_watermark | type == "number" and . >= 0 and floor == .)
    and (.remote_watermark | type == "number" and . >= 0 and floor == .)
  ' "${file}" >/dev/null
}

node_summary_is_empty_cordoned() {
  local summary_file="$1" node_id="$2"
  jq -e --arg node "${node_id}" '
    .node.id == $node and .node.state == "cordoned"
    and .node.capacity.cpus == 1 and .node.capacity.memory_mib == 1024
    and .assigned_cats == 0 and .assigned_cpus == 0
    and .assigned_memory_mib == 0 and .orphan_cats == 0
  ' "${summary_file}" >/dev/null
}

node_summary_has_only_cat() {
  local summary_file="$1" cats_file="$2" node_id="$3" cat_id="$4" cat_name="$5" workspace_id="$6"
  jq -e --arg node "${node_id}" '
    .node.id == $node and .node.state == "cordoned"
    and .node.capacity.cpus == 1 and .node.capacity.memory_mib == 1024
    and .assigned_cats == 1 and .assigned_cpus == 1
    and .assigned_memory_mib == 1024 and .orphan_cats == 0
  ' "${summary_file}" >/dev/null &&
    jq -e --arg node "${node_id}" --arg id "${cat_id}" --arg name "${cat_name}" \
      --arg workspace "${workspace_id}" '
      type == "array" and length == 1
      and .[0].cat.id == $id and .[0].cat.name == $name
      and .[0].cat.workspace_id == $workspace and .[0].cat.node_id == $node
      and .[0].cat.spec.cpus == 1 and .[0].cat.spec.memory_mib == 1024
    ' "${cats_file}" >/dev/null
}

iso_to_epoch() {
  perl -MTime::Local=timegm -e '
    my $s = shift;
    $s =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/ or exit 2;
    print timegm($6, $5, $4, $3, $2 - 1, $1), "\n";
  ' "$1"
}

iso_to_epoch_ms() {
  perl -MTime::Local=timegm -e '
    my $s = shift;
    $s =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/ or exit 2;
    my $fraction = defined($7) ? substr($7 . "000", 0, 3) : "000";
    print(timegm($6, $5, $4, $3, $2 - 1, $1) * 1000 + $fraction, "\n");
  ' "$1"
}

# Before create returns an immutable Cat ID, the adapter scope must be wholly
# unbound even though the harness has already selected the future q124 name.
# Once an ID exists, ID and name are always passed as one validated pair.
admin_cat_scope() {
  local cat_name="$1" cat_id="$2"
  if [[ -z "${cat_id}" ]]; then
    printf '|\n'
    return 0
  fi
  [[ "${cat_id}" =~ ^cat_[A-Za-z0-9_-]+$ && "${cat_name}" =~ ^q124-[a-z0-9-]+$ ]] || return 1
  printf '%s|%s\n' "${cat_id}" "${cat_name}"
}

invoke_admin_node_hook() {
  local hook="$1" action="$2" node_id="$3" cat_name="$4" cat_id="$5"
  local scope scope_cat_id scope_cat_name
  scope="$(admin_cat_scope "${cat_name}" "${cat_id}")" || {
    echo "refusing incomplete current Cat adapter scope" >&2
    return 2
  }
  scope_cat_id="${scope%%|*}"
  scope_cat_name="${scope#*|}"
  CATS_HA_HOOK_WORKSPACE_ID="${WORKSPACE_ID}" \
    CATS_HA_HOOK_CAT_ID="${scope_cat_id}" \
    CATS_HA_HOOK_CAT_NAME="${scope_cat_name}" \
    CATS_HA_WINDOW_NONCE="${WINDOW_NONCE}" \
    "${hook}" "${action}" "${node_id}"
}

validate_fixtures() {
  local fixture_root cat_file operation_file stale_file watermark_file log_file handoff_iso handoff_epoch
  local node_empty node_empty_cats node_owned node_owned_cats node_raced_cats
  local harness_self call_log stub_bin stub_hook scope_log live_block_log adapter_file scope scope_hook scope_output
  local WORKSPACE_ID="ws_788c5bfc3931"
  fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/cats-ha-fixture.XXXXXX")"
  FIXTURE_ROOT="${fixture_root}"
  trap 'rm -rf -- "${FIXTURE_ROOT}"' EXIT
  cat_file="${fixture_root}/cat.json"
  operation_file="${fixture_root}/operation.json"
  stale_file="${fixture_root}/stale-operation.json"
  watermark_file="${fixture_root}/watermark.json"
  log_file="${fixture_root}/workflow.log"
  node_empty="${fixture_root}/node-empty.json"
  node_empty_cats="${fixture_root}/node-empty-cats.json"
  node_owned="${fixture_root}/node-owned.json"
  node_owned_cats="${fixture_root}/node-owned-cats.json"
  node_raced_cats="${fixture_root}/node-raced-cats.json"
  harness_self="$(pwd)/test-results/qualification-20260805/ha-handoff.sh"
  call_log="${fixture_root}/forbidden-calls.log"
  stub_bin="${fixture_root}/bin"
  stub_hook="${fixture_root}/admin-hook"
  scope_log="${fixture_root}/wrong-workspace.log"
  adapter_file="deploy/aws/qualification/q124-admin-node-runner.sh"
  "${adapter_file}" --validate-scope-fixtures
  scope="$(admin_cat_scope q124-before-create '')"
  [[ "${scope}" == '|' ]] || {
    echo "before-create name was not converted to wholly unbound adapter scope" >&2
    return 1
  }
  scope="$(admin_cat_scope q124-created cat_fixture)"
  [[ "${scope}" == 'cat_fixture|q124-created' ]] || return 1
  if admin_cat_scope '' cat_fixture >/dev/null; then
    echo "harness scope builder accepted an ID without a Cat name" >&2
    return 1
  fi
  scope_hook="${fixture_root}/scope-hook"
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s|%s|%s|%s|%s\n" "${CATS_HA_HOOK_WORKSPACE_ID}" "${CATS_HA_HOOK_CAT_ID}" "${CATS_HA_HOOK_CAT_NAME}" "$1" "$2"' \
    >"${scope_hook}"
  chmod 700 "${scope_hook}"
  scope_output="$(invoke_admin_node_hook "${scope_hook}" get q124-fixture-node q124-before-create '')"
  [[ "${scope_output}" == 'ws_788c5bfc3931|||get|q124-fixture-node' ]] || {
    echo "before-create real adapter environment path retained a half-bound Cat scope" >&2
    return 1
  }
  scope_output="$(invoke_admin_node_hook "${scope_hook}" get q124-fixture-node q124-created cat_fixture)"
  [[ "${scope_output}" == 'ws_788c5bfc3931|cat_fixture|q124-created|get|q124-fixture-node' ]] || return 1
  mkdir -p "${stub_bin}"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\\n" "$(basename "$0") $*" >>"${Q124_CALL_LOG}"' 'exit 99' \
    >"${stub_bin}/cats"
  cp "${stub_bin}/cats" "${stub_bin}/gh"
  cp "${stub_bin}/cats" "${stub_hook}"
  chmod 700 "${stub_bin}/cats" "${stub_bin}/gh" "${stub_hook}"
  if env PATH="${stub_bin}:${PATH}" Q124_CALL_LOG="${call_log}" \
    CATS_BIN="${stub_bin}/cats" CATS_HA_ADMIN_NODE_HOOK="${stub_hook}" \
    CATS_HA_EXECUTE=RUN_ISSUE_124_HA_HANDOFF \
    CATS_SUT_RELEASE_SHA=1111111111111111111111111111111111111111 \
    CATS_SUT_DEPLOY_RUN_ID=1 CATS_SUT_WORKSPACE_ID=ws_wrong \
    CATS_TEST_WORKSPACE=default/wrong CATS_HA_REQUIRED_NODE_ID=q124-fixture-node \
    "${harness_self}" >"${scope_log}" 2>&1; then
    echo "wrong workspace unexpectedly reached live execution" >&2
    return 1
  fi
  [[ ! -s "${call_log}" ]] || {
    echo "wrong workspace invoked Cats/admin/dispatch: $(<"${call_log}")" >&2
    return 1
  }
  rg -Fq 'CATS_SUT_WORKSPACE_ID must be exactly ws_788c5bfc3931' "${scope_log}"

  : >"${call_log}"
  live_block_log="${fixture_root}/live-block.log"
  if env PATH="${stub_bin}:${PATH}" Q124_CALL_LOG="${call_log}" \
    CATS_BIN="${stub_bin}/cats" CATS_HA_ADMIN_NODE_HOOK="${stub_hook}" \
    CATS_HA_EXECUTE=RUN_ISSUE_124_HA_HANDOFF \
    CATS_SUT_RELEASE_SHA=1111111111111111111111111111111111111111 \
    CATS_SUT_DEPLOY_RUN_ID=1 CATS_SUT_WORKSPACE_ID=ws_788c5bfc3931 \
    CATS_TEST_WORKSPACE=default/qual-124-20260805 CATS_HA_REQUIRED_NODE_ID=q124-fixture-node \
    "${harness_self}" >"${live_block_log}" 2>&1; then
    echo "incomplete external recovery boundary unexpectedly reached live execution" >&2
    return 1
  fi
  [[ ! -s "${call_log}" ]] || {
    echo "DO NOT LIVE gate invoked Cats/admin/dispatch: $(<"${call_log}")" >&2
    return 1
  }
  rg -Fq 'DO NOT LIVE: HA control actions require a nonce-bound independent re-cordon watchdog' "${live_block_log}"

  printf '%s\n' '{"id":"cat_fixture","desired_state":"running","observed_state":"starting","generation":7}' >"${cat_file}"
  printf '%s\n' '{"id":"op_fixture","resource_id":"cat_fixture","resource_generation":7,"phase":"running"}' >"${operation_file}"
  printf '%s\n' '{"id":"op_stale","resource_id":"cat_fixture","resource_generation":6,"phase":"running"}' >"${stale_file}"
  printf '%s\n' '{"cat_id":"cat_fixture","node_id":"q124-fixture-node","local_watermark":9,"remote_watermark":8}' >"${watermark_file}"
  printf '%s\n' '{"node":{"id":"q124-fixture-node","state":"cordoned","capacity":{"cpus":1,"memory_mib":1024}},"assigned_cats":0,"assigned_cpus":0,"assigned_memory_mib":0,"orphan_cats":0}' >"${node_empty}"
  printf '%s\n' '[]' >"${node_empty_cats}"
  printf '%s\n' '{"node":{"id":"q124-fixture-node","state":"cordoned","capacity":{"cpus":1,"memory_mib":1024}},"assigned_cats":1,"assigned_cpus":1,"assigned_memory_mib":1024,"orphan_cats":0}' >"${node_owned}"
  printf '%s\n' '[{"cat":{"id":"cat_fixture","name":"q124-fixture-cat","workspace_id":"ws_fixture","node_id":"q124-fixture-node","spec":{"cpus":1,"memory_mib":1024}}}]' >"${node_owned_cats}"
  printf '%s\n' '[{"cat":{"id":"cat_fixture","name":"q124-fixture-cat","workspace_id":"ws_fixture","node_id":"q124-fixture-node","spec":{"cpus":1,"memory_mib":1024}}},{"cat":{"id":"cat_user","name":"user-cat","workspace_id":"ws_user","node_id":"q124-fixture-node","spec":{"cpus":0,"memory_mib":0}}}]' >"${node_raced_cats}"
  printf '%s\n' \
    'drill Delete leader 2026-08-05T12:00:01.100Z Reconciler leader before disruption: cats-controld-old (10.0.0.1)' \
    'drill Delete leader 2026-08-05T12:00:02.000Z Lifecycle coordinator locked token=q124-fixture-token operation=op_aaaaaaaaaaaa locked_at=2026-08-05T12:00:01.900Z' \
    'drill Delete leader 2026-08-05T12:00:03.000Z Deleting lifecycle-locked leader: cats-controld-old uid=fixture operation=op_aaaaaaaaaaaa deletion_at=2026-08-05T12:00:02.900Z' \
    'drill Delete leader 2026-08-05T12:00:04.000Z Lifecycle coordinator released token=q124-fixture-token operation=op_aaaaaaaaaaaa released_at=2026-08-05T12:00:03.900Z' \
    'drill Delete leader 2026-08-05T12:00:05.000Z Lifecycle exact operation converged token=q124-fixture-token operation=op_aaaaaaaaaaaa generation=7 final_state=running' \
    'drill Verify takeover 2026-08-05T12:00:06.900Z Reconciler leader after disruption: cats-controld-new (10.0.0.2)' \
    'drill Delete leader 2026-08-05T12:00:05.000Z All 240 public health probes succeeded during leader replacement.' \
    >"${log_file}"

  transition_matches "${cat_file}" "${operation_file}" running starting
  if transition_matches "${cat_file}" "${stale_file}" running starting; then
    echo "fixture validation accepted a stale resource_generation" >&2
    return 1
  fi
  watermark_probe_matches_cat_node "${watermark_file}" cat_fixture q124-fixture-node
  if watermark_probe_matches_cat_node "${watermark_file}" cat_fixture q124-wrong-node; then
    echo "fixture validation accepted a watermark from the wrong Node" >&2
    return 1
  fi
  watermark_is_relaxed_backlog "${watermark_file}"
  printf '%s\n' '{"cat_id":"cat_fixture","node_id":"q124-fixture-node","local_watermark":9,"remote_watermark":9}' >"${watermark_file}"
  if watermark_is_relaxed_backlog "${watermark_file}"; then
    echo "fixture validation accepted R=L" >&2
    return 1
  fi
  node_summary_is_empty_cordoned "${node_empty}" q124-fixture-node
  jq -e 'type == "array" and length == 0' "${node_empty_cats}" >/dev/null
  node_summary_has_only_cat "${node_owned}" "${node_owned_cats}" q124-fixture-node \
    cat_fixture q124-fixture-cat ws_fixture
  if node_summary_has_only_cat "${node_owned}" "${node_raced_cats}" q124-fixture-node \
    cat_fixture q124-fixture-cat ws_fixture; then
    echo "fixture validation accepted a user Cat placement race" >&2
    return 1
  fi
  handoff_iso="$(perl -ne 'if (/([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z).*Reconciler leader before disruption:/) { print "$1\n"; exit }' "${log_file}")"
  handoff_epoch="$(iso_to_epoch "${handoff_iso}")"
  [[ "${handoff_epoch}" == 1785931201 ]]
  [[ "$(awk 'index($0,"Reconciler leader before disruption:"){n++} END{print n+0}' "${log_file}")" -eq 1 ]]
  [[ "$(awk 'index($0,"Reconciler leader after disruption:"){n++} END{print n+0}' "${log_file}")" -eq 1 ]]
  [[ "$(awk 'index($0,"All 240 public health probes succeeded"){n++} END{print n+0}' "${log_file}")" -eq 1 ]]
  [[ "$(awk 'index($0,"Lifecycle coordinator locked token=q124-fixture-token"){n++} END{print n+0}' "${log_file}")" -eq 1 ]]
  [[ "$(awk 'index($0,"Deleting lifecycle-locked leader:"){n++} END{print n+0}' "${log_file}")" -eq 1 ]]
  [[ "$(awk 'index($0,"Lifecycle exact operation converged token=q124-fixture-token"){n++} END{print n+0}' "${log_file}")" -eq 1 ]]
  # The reviewed workflow must keep coordination opt-in and retain all
  # fail-closed lock, TTL, UID and exact-convergence guards.
  workflow_file=".github/workflows/verify-control-plane-ha.yml"
  [[ -f "${workflow_file}" ]]
  for workflow_guard in \
    'default: "disabled"' \
    'mode == '\''disrupt'\''' \
    'uses: actions/checkout@v4' \
    'LOCK_Q124_LIFECYCLE' \
    'ws_788c5bfc3931' \
    'activeDeadlineSeconds: 300' \
    'FOR UPDATE OF c' \
    'PERFORM pg_sleep(90)' \
    'refusing to delete lifecycle coordinator with an unverified UID' \
    'deploy/aws/select-reconciler-owner.sh' \
    'deploy/aws/evict-pod-with-uid.sh cats "$target" "$target_uid"' \
    'leader deletion was not enclosed by the lifecycle row-lock interval' \
    'CATS_HA_EXACT_OPERATION_CONVERGED'; do
    rg -Fq "${workflow_guard}" "${workflow_file}"
  done
  rm -rf -- "${FIXTURE_ROOT}"
  trap - EXIT
  printf 'fixture_validation=PASS adapter_scope_empty=true adapter_scope_paired=true adapter_scope_half_rejected=true before_create_scope_unbound=true wrong_workspace_zero_calls=true incomplete_recovery_boundary_zero_calls=true transition_generation=true stale_rejected=true relaxed_backlog=true watermark_node_bound=true node_empty=true node_exact_cat=true user_cat_race_rejected=true workflow_log=true\n'
}

dry_run() {
  local durability scenario round source transitional target watermark node_gate
  node_gate=BLOCKED-required-q124-node-and-admin-hook
  if [[ -n "${REQUIRED_NODE_ID}" && -n "${ADMIN_NODE_HOOK}" ]]; then
    node_gate=required-node-configured
  fi
  printf 'mode=dry-run mutation=NONE workflow=%s rounds=%s workspace=%s sut_sha=%s deploy_run=%s required_node=%s\n' \
    "${HA_WORKFLOW}" "${ROUNDS}" "${WORKSPACE}" "${SUT_RELEASE_SHA:-UNSET}" "${SUT_DEPLOY_RUN_ID:-UNSET}" \
    "${REQUIRED_NODE_ID:-UNSET}"
  printf 'round\tdurability\tscenario\tsource\ttransitional\ttarget\twatermark_precondition\tnode_gate\n'
  for durability in ${DURABILITIES}; do
    for scenario in ${SCENARIOS}; do
      watermark=not-required
      if [[ "${durability}" == relaxed && ("${scenario}" == resume || "${scenario}" == restore) ]]; then
        if [[ -n "${WATERMARK_PROBE_CMD}" ]]; then
          watermark=required-configured
        else
          watermark=BLOCKED-no-public-watermark-probe
        fi
      fi
      source="$(scenario_source "${scenario}")"
      transitional="$(scenario_transition "${scenario}")"
      target="$(scenario_target "${scenario}")"
      for ((round = 1; round <= ROUNDS; round++)); do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "${round}" "${durability}" "${scenario}" "${source}" "${transitional}" "${target}" "${watermark}" "${node_gate}"
      done
    done
  done
  printf 'dry_run=PASS no_cats_calls=true no_admin_hook_calls=true no_gh_dispatch=true no_kubectl=true user_cat_race=fail-closed leave_required_node_cordoned=true forbidden_node_actions=drain,fence,delete\n'
}

validate_static
if [[ "${MODE}" == live ]]; then
  # This pure-shell gate deliberately precedes every command lookup, Cats call,
  # admin-hook call and workflow dispatch.
  validate_live_locator_scope
  die "DO NOT LIVE: HA control actions require a nonce-bound independent re-cordon watchdog before every uncordon"
fi
require_command jq
require_command perl
require_command awk
require_command mktemp
require_command rm
require_command rg
if [[ "${MODE}" == fixture ]]; then
  validate_fixtures
  exit 0
fi
if [[ "${MODE}" == dry-run ]]; then
  dry_run
  exit 0
fi

[[ "${EXECUTE_CONFIRMATION}" == "RUN_ISSUE_124_HA_HANDOFF" ]] ||
  die "live mode requires CATS_HA_EXECUTE=RUN_ISSUE_124_HA_HANDOFF"
[[ "${SUT_RELEASE_SHA}" =~ ^[0-9a-f]{40}$ ]] ||
  die "CATS_SUT_RELEASE_SHA must be a full lowercase Git SHA"
[[ "${SUT_DEPLOY_RUN_ID}" =~ ^[1-9][0-9]*$ ]] ||
  die "CATS_SUT_DEPLOY_RUN_ID must be a non-zero workflow run ID"
[[ "${REQUIRED_NODE_ID}" =~ ^q124-[a-z0-9][a-z0-9-]{7,54}$ ]] ||
  die "live mode requires CATS_HA_REQUIRED_NODE_ID=q124-*"
if [[ " ${DURABILITIES} " == *" relaxed " \
   && (" ${SCENARIOS} " == *" resume " || " ${SCENARIOS} " == *" restore ") \
   && -z "${WATERMARK_PROBE_CMD}" ]]; then
  die "live Relaxed resume/restore requires a reviewed CATS_WATERMARK_PROBE_CMD; coverage may not be downgraded"
fi
export GH_REPO="${GITHUB_REPOSITORY}"
require_command gh
require_command curl
require_command awk
require_command rg
require_command sed
require_command sort
require_command tee
require_command git
require_command tr
require_command shasum
verify_admin_hook_provenance
[[ -x "${CATS_BIN}" ]] || die "CATS_BIN is not executable: ${CATS_BIN}"

mkdir -p "${RUN_DIR}/cases"
SUMMARY="${RUN_DIR}/summary.log"
CASES_TSV="${RUN_DIR}/cases.tsv"
OWNED_TSV="${RUN_DIR}/owned-cats.tsv"
RESULT_TSV="${RUN_DIR}/result.tsv"
GUARD_LOG="${RUN_DIR}/deployment-guard.log"
GUARD_FAILED="${RUN_DIR}/deployment-guard-failed"
: >"${OWNED_TSV}"
printf 'round\tdurability\tscenario\tcat\tcat_id\tgeneration\toperation_id\tresource_generation\ttransition_unix\thandoff_unix\tworkflow_run_id\tresult\n' >"${CASES_TSV}"
exec > >(tee -a "${SUMMARY}") 2>&1

CURRENT_CAT=""
CURRENT_CAT_ID=""
CURRENT_CASE_DIR=""
CURRENT_OPERATION=""
CURRENT_WORKFLOW_RUN=""
SUBMITTED_OPERATION_ID=""
COORDINATION_TOKEN=""
WORKFLOW_DISPATCHED_AT=""
CURRENT_SCENARIO=""
CURRENT_DURABILITY=""
CURRENT_ROUND=""
PUBLIC_PROBE_PID=""
PUBLIC_PROBE_STOP=""
GUARD_PID=""
FAILURE_DOMAIN=functional
NODE_UNCORDONED=false

cats_json() {
  "${CATS_BIN}" --workspace "${WORKSPACE}" --json "$@"
}

# The separately reviewed independent-runner adapter owns transient
# administrator authentication and accepts
# exactly: get NODE, cats NODE, cordon NODE, or uncordon NODE. It must write
# only the corresponding API JSON to stdout and must never print credentials.
admin_node_json() {
  local action="$1" output
  case "${action}" in
    get|cats|cordon|uncordon) ;;
    *) echo "refusing unsupported admin-node hook action: ${action}" >&2; return 2 ;;
  esac
  # Re-hash immediately before every adapter call so a replacement never
  # reaches get, cats, cordon or uncordon.
  verify_admin_hook_provenance
  output="$(invoke_admin_node_hook "${ADMIN_NODE_HOOK}" "${action}" "${REQUIRED_NODE_ID}" \
    "${CURRENT_CAT}" "${CURRENT_CAT_ID}")" || return
  case "${output,,}" in
    *authorization:*|*bearer\ *|*set-cookie:*|*x-amz-security-token*|*aws_access_key*|*aws_secret_access_key*)
      echo "admin-node hook emitted secret-like output; refusing to retain it" >&2
      return 1
      ;;
  esac
  printf '%s\n' "${output}"
}

validate_node_summary_identity() {
  local file="$1" expected_state="$2"
  jq -e --arg node "${REQUIRED_NODE_ID}" --arg state "${expected_state}" '
    .node.id == $node and .node.state == $state
    and .node.capacity.cpus == 1 and .node.capacity.memory_mib == 1024
    and (.assigned_cats | type == "number")
    and (.assigned_cpus | type == "number")
    and (.assigned_memory_mib | type == "number")
    and (.orphan_cats | type == "number")
  ' "${file}" >/dev/null
}

capture_node_empty_cordoned() {
  local label="$1" evidence_dir="${2:-${CURRENT_CASE_DIR}}" summary_file cats_file
  summary_file="${evidence_dir}/node-${label}.json"
  cats_file="${evidence_dir}/node-${label}-cats.json"
  admin_node_json get >"${summary_file}"
  admin_node_json cats >"${cats_file}"
  node_summary_is_empty_cordoned "${summary_file}" "${REQUIRED_NODE_ID}" || {
    echo "required Node is not exact Cordoned/empty/zero-orphan 1 CPU/1 GiB: ${REQUIRED_NODE_ID}" >&2
    return 1
  }
  jq -e 'type == "array" and length == 0' "${cats_file}" >/dev/null || {
    echo "required Node exact assignment set is not empty; leaving it Cordoned" >&2
    return 1
  }
  printf 'required_node_empty=PASS node=%s label=%s\n' "${REQUIRED_NODE_ID}" "${label}"
}

capture_node_has_current_cat() {
  local label="$1" evidence_dir="${2:-${CURRENT_CASE_DIR}}" summary_file cats_file
  summary_file="${evidence_dir}/node-${label}.json"
  cats_file="${evidence_dir}/node-${label}-cats.json"
  admin_node_json get >"${summary_file}"
  admin_node_json cats >"${cats_file}"
  node_summary_has_only_cat "${summary_file}" "${cats_file}" "${REQUIRED_NODE_ID}" \
    "${CURRENT_CAT_ID}" "${CURRENT_CAT}" "${WORKSPACE_ID}" || {
    echo "required Node assignment is not the one exact current q124 Cat; possible user placement race; leaving it Cordoned" >&2
    return 1
  }
  printf 'required_node_exact_cat=PASS node=%s cat=%s label=%s\n' \
    "${REQUIRED_NODE_ID}" "${CURRENT_CAT_ID}" "${label}"
}

capture_node_for_cat_state() {
  local label="$1" cat_file="$2" node_id
  node_id="$(jq -r '.node_id // empty' "${cat_file}")"
  if [[ -z "${node_id}" ]]; then
    capture_node_empty_cordoned "${label}"
  else
    [[ "${node_id}" == "${REQUIRED_NODE_ID}" ]] || {
      printf 'cat_node=FAIL expected=%s actual=%s label=%s\n' \
        "${REQUIRED_NODE_ID}" "${node_id}" "${label}" >&2
      return 1
    }
    capture_node_has_current_cat "${label}"
  fi
}

uncordon_required_node() {
  local label="$1" evidence
  assert_guard_ok
  # Set this before the call: a transport failure may occur after the server
  # accepted the uncordon, so every exit path must conservatively re-cordon.
  NODE_UNCORDONED=true
  evidence="${CURRENT_CASE_DIR}/node-${label}-uncordon.json"
  admin_node_json uncordon >"${evidence}"
  validate_node_summary_identity "${evidence}" ready
  printf 'required_node_uncordoned=PASS node=%s label=%s\n' "${REQUIRED_NODE_ID}" "${label}"
}

cordon_required_node() {
  local label="$1" evidence
  evidence="${CURRENT_CASE_DIR:-${RUN_DIR}}/node-${label}-cordon.json"
  if admin_node_json cordon >"${evidence}" && validate_node_summary_identity "${evidence}" cordoned; then
    NODE_UNCORDONED=false
    printf 'required_node_cordoned=PASS node=%s label=%s\n' "${REQUIRED_NODE_ID}" "${label}"
    return 0
  fi
  echo "failed to prove required Node Cordoned: ${REQUIRED_NODE_ID}" >&2
  return 1
}

assert_guard_ok() {
  [[ ! -e "${GUARD_FAILED}" ]] || {
    echo "deployment identity guard failed; refusing further mutation" >&2
    return 1
  }
}

deployment_guard() {
  local snapshot active latest_id latest_sha latest_status latest_conclusion
  snapshot="$(gh run list --workflow 'Deploy production' --limit 10 \
    --json databaseId,status,conclusion,headSha,createdAt,updatedAt)" || return 1
  printf '%s' "${snapshot}" | jq -e 'type == "array" and length > 0' >/dev/null || return 1
  active="$(printf '%s' "${snapshot}" | jq '[.[] | select(.status != "completed")] | length')" || return 1
  latest_id="$(printf '%s' "${snapshot}" | jq -r '.[0].databaseId')" || return 1
  latest_sha="$(printf '%s' "${snapshot}" | jq -r '.[0].headSha')" || return 1
  latest_status="$(printf '%s' "${snapshot}" | jq -r '.[0].status')" || return 1
  latest_conclusion="$(printf '%s' "${snapshot}" | jq -r '.[0].conclusion')" || return 1
  [[ "${active}" -eq 0 && "${latest_id}" == "${SUT_DEPLOY_RUN_ID}" \
     && "${latest_sha}" == "${SUT_RELEASE_SHA}" && "${latest_status}" == completed \
     && "${latest_conclusion}" == success ]] || {
    printf 'deployment_guard=FAIL expected_run=%s expected_sha=%s actual_run=%s actual_sha=%s active=%s status=%s conclusion=%s\n' \
      "${SUT_DEPLOY_RUN_ID}" "${SUT_RELEASE_SHA}" "${latest_id}" "${latest_sha}" \
      "${active}" "${latest_status}" "${latest_conclusion}" >&2
    return 1
  }
  printf 'deployment_guard=PASS utc=%s run=%s sha=%s\n' \
    "$(date -u +%FT%TZ)" "${latest_id}" "${latest_sha}"
}

guard_watch() {
  while true; do
    if ! deployment_guard >>"${GUARD_LOG}" 2>&1; then
      : >"${GUARD_FAILED}"
      return 1
    fi
    sleep 5
  done
}

stop_guard_watch() {
  if [[ -n "${GUARD_PID}" ]]; then
    kill "${GUARD_PID}" 2>/dev/null || true
    wait "${GUARD_PID}" 2>/dev/null || true
    GUARD_PID=""
  fi
}

start_public_probe() {
  local evidence="$1"
  PUBLIC_PROBE_STOP="${evidence}.stop"
  rm -f -- "${PUBLIC_PROBE_STOP}"
  printf 'utc\thttp_code\ttime_total\tcurl_rc\n' >"${evidence}"
  (
    set +e
    while [[ ! -e "${PUBLIC_PROBE_STOP}" ]]; do
      output="$(curl --silent --show-error --output /dev/null \
        --connect-timeout 2 --max-time 3 --write-out '%{http_code}\t%{time_total}' \
        "${SUT_API_ORIGIN}/healthz" 2>/dev/null)"
      rc=$?
      [[ -n "${output}" ]] || output=$'000\t0'
      printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "${output}" "${rc}" >>"${evidence}"
      sleep 0.25
    done
  ) &
  PUBLIC_PROBE_PID=$!
}

stop_public_probe() {
  if [[ -n "${PUBLIC_PROBE_PID}" ]]; then
    : >"${PUBLIC_PROBE_STOP}"
    wait "${PUBLIC_PROBE_PID}" 2>/dev/null || true
    PUBLIC_PROBE_PID=""
  fi
}

assert_public_probe() {
  local evidence="$1" rows failures
  rows="$(awk 'NR > 1 {n++} END{print n+0}' "${evidence}")"
  failures="$(awk -F '\t' 'NR > 1 && ($2 != "200" || $4 != "0") {n++} END{print n+0}' "${evidence}")"
  (( rows > 0 && failures == 0 )) || {
    printf 'public_probe=FAIL rows=%s failures=%s evidence=%s\n' "${rows}" "${failures}" "${evidence}" >&2
    return 1
  }
  printf 'public_probe=PASS rows=%s failures=0\n' "${rows}"
}

submit_operation() {
  local action="$1" cat_name="$2" output_file="$3" output operation_id
  SUBMITTED_OPERATION_ID=""
  output="$("${CATS_BIN}" --workspace "${WORKSPACE}" --json --no-wait "${action}" "${cat_name}")"
  printf '%s\n' "${output}" >"${output_file}"
  operation_id="$(printf '%s\n' "${output}" | awk '$1 == "operation" && $3 == "accepted" {print $2}')"
  [[ "${operation_id}" == op_* ]] || {
    echo "could not parse accepted ${action} operation id" >&2
    return 1
  }
  SUBMITTED_OPERATION_ID="${operation_id}"
}

wait_operation_terminal() {
  local operation_id="$1" output_file="$2" deadline operation phase
  deadline="$(( $(date +%s) + OP_TIMEOUT_SECONDS ))"
  while true; do
    assert_guard_ok || return 1
    if operation="$(cats_json operation get "${operation_id}" 2>&1)"; then
      printf '%s\n' "${operation}" >"${output_file}"
      phase="$(printf '%s' "${operation}" | jq -r '.phase')" || return 1
      case "${phase}" in
        succeeded) return 0 ;;
        failed)
          echo "operation ${operation_id} failed" >&2
          return 1
          ;;
        pending|running) ;;
        *) echo "unknown operation phase ${phase} for ${operation_id}" >&2; return 1 ;;
      esac
    else
      printf '%s\n' "${operation}" >>"${output_file}.poll-errors"
    fi
    (( $(date +%s) < deadline )) || {
      echo "operation ${operation_id} did not become terminal" >&2
      return 124
    }
    sleep 1
  done
}

submit_and_wait_setup() {
  local action="$1" cat_name="$2" label="$3" operation_id
  submit_operation "${action}" "${cat_name}" "${CURRENT_CASE_DIR}/setup-${label}-accepted.log"
  operation_id="${SUBMITTED_OPERATION_ID}"
  wait_operation_terminal "${operation_id}" "${CURRENT_CASE_DIR}/setup-${label}-operation.json"
}

capture_guest_sentinel() {
  local label="$1"
  cats_json exec "${CURRENT_CAT}" --timeout 180 -- /bin/sh -lc '
    set -eu
    test "$(cat /var/lib/q124-ha/identity)" = "'"${CURRENT_CAT}"'"
    test -s /var/lib/q124-ha/journal
    systemctl is-active --quiet q124-ha-sentinel.service
    first=$(cat /var/lib/q124-ha/counter)
    sleep 1
    second=$(cat /var/lib/q124-ha/counter)
    test "$second" -gt "$first"
    printf "identity\t%s\n" "$(cat /var/lib/q124-ha/identity)"
    printf "counter\t%s\n" "$second"
    printf "boot\t%s\n" "$(cat /proc/sys/kernel/random/boot_id)"
    digest=$(sha256sum /var/lib/q124-ha/journal)
    printf "digest\t%s\n" "${digest%% *}"
  ' >"${CURRENT_CASE_DIR}/guest-${label}.tsv"
}

probe_public_route() {
  local label="$1" expected_code="$2" hostname headers body code rc epoch deadline valid
  hostname="$(jq -r 'if length == 1 then .[0].hostname else empty end' \
    "${CURRENT_CASE_DIR}/route-created.json")"
  [[ "${hostname}" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  headers="${CURRENT_CASE_DIR}/route-${label}.headers"
  body="${CURRENT_CASE_DIR}/route-${label}.body"
  deadline="$(( $(date +%s) + ROUTE_TIMEOUT_SECONDS ))"
  while true; do
    set +e
    code="$(curl --silent --show-error --dump-header "${headers}" --output "${body}" \
      --connect-timeout 5 --max-time 10 --write-out '%{http_code}' "https://${hostname}/")"
    rc=$?
    set -e
    epoch="$(awk 'tolower($1)=="x-cats-route-epoch:" {gsub("\\r", "", $2); value=$2} END{print value}' "${headers}")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "${label}" \
      "${hostname}" "${code:-000}" "${rc}" "${epoch:-NULL}" >>"${CURRENT_CASE_DIR}/route-probes.tsv"
    valid=false
    if [[ "${rc}" -eq 0 && "${code}" == "${expected_code}" ]]; then
      if [[ "${expected_code}" == 200 \
         && "$(tr -d '\r\n' <"${body}")" == q124-ha && "${epoch}" =~ ^[0-9]+$ ]]; then
        valid=true
      elif [[ "${expected_code}" == 503 ]] \
        && rg -q 'endpoint does not wake|endpoint asleep' "${body}"; then
        valid=true
      fi
    fi
    [[ "${valid}" != true ]] || return 0
    (( $(date +%s) < deadline )) || {
      printf 'route_probe=FAIL label=%s expected=%s code=%s curl_rc=%s\n' \
        "${label}" "${expected_code}" "${code:-000}" "${rc}" >&2
      return 1
    }
    sleep 0.5
  done
}

create_case_cat() {
  local durability="$1" create_file cat_file listed create_rc=0
  create_file="${CURRENT_CASE_DIR}/create.log"
  cat_file="${CURRENT_CASE_DIR}/cat-created.json"

  # This is both a positive control for the admin adapter and the safety gate
  # for the only scheduling window. A foreign assignment or orphan stops the
  # run while the temporary Node remains Cordoned.
  capture_node_empty_cordoned before-create
  if existing="$(cats_json get "${CURRENT_CAT}" 2>&1)"; then
    printf '%s\n' "${existing}" >"${CURRENT_CASE_DIR}/precreate-unexpected-positive.json"
    echo "refusing to reuse existing Cat ${CURRENT_CAT}" >&2
    return 1
  fi
  printf '%s\n' "${existing}" >"${CURRENT_CASE_DIR}/precreate-not-found.log"
  [[ "${existing}" == *"not found (NotFound)"* ]] || return 1

  # The Node is Ready only while the blocking create claims and boots this
  # exact 1 CPU/1 GiB Cat. NODE_UNCORDONED makes every error/interrupt path
  # re-cordon before waiting, probing or cleanup.
  uncordon_required_node create
  set +e
  cats_json create "${CURRENT_CAT}" --cpus 1 --memory 1GiB --root-size 1GiB \
    --no-auto-suspend --expires-in 14400 --durability "${durability}" >"${create_file}" 2>&1
  create_rc=$?
  set -e
  cordon_required_node after-create
  (( create_rc == 0 )) || {
    printf 'create_failed=FAIL rc=%s cat=%s; Node is Cordoned\n' "${create_rc}" "${CURRENT_CAT}" >&2
    return "${create_rc}"
  }
  cats_json get "${CURRENT_CAT}" >"${cat_file}"
  jq -e --arg name "${CURRENT_CAT}" --arg workspace "${WORKSPACE_ID}" \
    --arg node "${REQUIRED_NODE_ID}" '
    .name == $name and .workspace_id == $workspace
    and .desired_state == "running" and .observed_state == "running"
    and .node_id == $node
    and (.id | type == "string" and startswith("cat_"))
  ' "${cat_file}" >/dev/null
  CURRENT_CAT_ID="$(jq -r '.id' "${cat_file}")"
  printf '%s\t%s\t%s\n' "${CURRENT_CAT}" "${CURRENT_CAT_ID}" "${CURRENT_CASE_DIR}" >>"${OWNED_TSV}"
  capture_node_has_current_cat after-create

  # Positive-calibrate the workspace list selector while the owned Cat is known
  # present. The same selector is used by the final zero-leftover check.
  listed="$(cats_json ls)"
  printf '%s\n' "${listed}" >"${CURRENT_CASE_DIR}/list-positive.json"
  printf '%s' "${listed}" | jq -e --arg id "${CURRENT_CAT_ID}" --arg name "${CURRENT_CAT}" '
    type == "array" and any(.[]; .id == $id and .name == $name)
  ' >/dev/null

  cats_json exec "${CURRENT_CAT}" --timeout 180 -- /bin/sh -lc '
    set -eu
    install -d -m 0755 /var/lib/q124-ha
    printf "%s\n" "'"${CURRENT_CAT}"'" > /var/lib/q124-ha/identity
    dd if=/dev/urandom of=/var/lib/q124-ha/payload.bin bs=1M count=16 status=none
    sha256sum /var/lib/q124-ha/payload.bin > /var/lib/q124-ha/payload.sha256
    cat > /usr/local/sbin/q124-ha-sentinel <<"EOF"
#!/bin/sh
set -eu
i=0
test -f /var/lib/q124-ha/counter && i=$(cat /var/lib/q124-ha/counter)
while :; do
  i=$((i + 1))
  printf "%s %s\n" "$i" "$(date -u +%s%N)" >> /var/lib/q124-ha/journal
  printf "%s\n" "$i" > /var/lib/q124-ha/counter
  sync /var/lib/q124-ha/journal /var/lib/q124-ha/counter
  sleep 0.2
done
EOF
    chmod 0755 /usr/local/sbin/q124-ha-sentinel
    cat > /etc/systemd/system/q124-ha-sentinel.service <<"EOF"
[Unit]
Description=Issue 124 lifecycle HA I/O sentinel
After=local-fs.target
[Service]
ExecStart=/usr/local/sbin/q124-ha-sentinel
Restart=always
RestartSec=0
[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/q124-ha-http.socket <<"EOF"
[Unit]
Description=Issue 124 route oracle socket
[Socket]
ListenStream=65534
Accept=yes
[Install]
WantedBy=sockets.target
EOF
    cat > /etc/systemd/system/q124-ha-http@.service <<"EOF"
[Unit]
Description=Issue 124 route oracle response
[Service]
StandardInput=socket
StandardOutput=socket
ExecStart=/usr/local/sbin/q124-ha-http
EOF
    cat > /usr/local/sbin/q124-ha-http <<"EOF"
#!/bin/sh
printf "HTTP/1.1 200 OK\\r\\nContent-Length: 8\\r\\nConnection: close\\r\\n\\r\\nq124-ha\\n"
EOF
    chmod 0755 /usr/local/sbin/q124-ha-http
    systemctl daemon-reload
    systemctl enable --now q124-ha-sentinel.service
    systemctl enable --now q124-ha-http.socket
    sync
    sha256sum -c /var/lib/q124-ha/payload.sha256
  ' >"${CURRENT_CASE_DIR}/guest-seed.log"
  capture_guest_sentinel before

  cats_json expose "${CURRENT_CAT}" 65534 --name q124-ha --protocol http --no-wake \
    >"${CURRENT_CASE_DIR}/endpoint-create.log"
  cats_json endpoint ls "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/route-created.json"
  jq -e --arg id "${CURRENT_CAT_ID}" '
    type == "array" and length == 1
    and .[0].cat_id == $id and .[0].name == "q124-ha"
    and .[0].wake_policy == "no_wake"
  ' "${CURRENT_CASE_DIR}/route-created.json" >/dev/null
  printf 'utc\tlabel\thostname\thttp_code\tcurl_rc\troute_epoch\n' >"${CURRENT_CASE_DIR}/route-probes.tsv"
  probe_public_route created 200
}

prepare_source_state() {
  local scenario="$1" wanted route_code
  case "${scenario}" in
    start) submit_and_wait_setup stop "${CURRENT_CAT}" cold ;;
    resume) submit_and_wait_setup suspend "${CURRENT_CAT}" suspended ;;
    restore) submit_and_wait_setup warm "${CURRENT_CAT}" warm ;;
    suspend|warm|stop) ;;
  esac
  wanted="$(scenario_source "${scenario}")"
  cats_json get "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/cat-source.json"
  jq -e --arg wanted "${wanted}" '.desired_state == $wanted and .observed_state == $wanted' \
    "${CURRENT_CASE_DIR}/cat-source.json" >/dev/null
  cats_json endpoint ls "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/route-source.json"
  route_code=503
  [[ "${wanted}" != running ]] || route_code=200
  probe_public_route source "${route_code}"
}

prove_relaxed_watermark() {
  local sanitized deadline raw local_mark remote_mark
  [[ -n "${WATERMARK_PROBE_CMD}" ]] || return 6
  sanitized="${CURRENT_CASE_DIR}/watermark-before.json"
  deadline="$(( $(date +%s) + WATERMARK_TIMEOUT_SECONDS ))"
  while true; do
    if raw="$(CATS_WATERMARK_CAT_NAME="${CURRENT_CAT}" \
      CATS_WATERMARK_CAT_ID="${CURRENT_CAT_ID}" \
      CATS_WATERMARK_WORKSPACE_ID="${WORKSPACE_ID}" \
      CATS_WATERMARK_NODE_ID="${REQUIRED_NODE_ID}" \
      bash -c "${WATERMARK_PROBE_CMD}" 2>/dev/null)"; then
      if printf '%s' "${raw}" | jq -e --arg cat "${CURRENT_CAT_ID}" --arg node "${REQUIRED_NODE_ID}" '
          .cat_id == $cat and .node_id == $node
          and (.local_watermark | type == "number" and . >= 0 and floor == .)
          and (.remote_watermark | type == "number" and . >= 0 and floor == .)
        ' >/dev/null \
        && local_mark="$(printf '%s' "${raw}" | jq -er '.local_watermark')" \
        && remote_mark="$(printf '%s' "${raw}" | jq -er '.remote_watermark')"; then
        jq -n --argjson local "${local_mark}" --argjson remote "${remote_mark}" \
          '{local_watermark:$local,remote_watermark:$remote}' >"${sanitized}"
        if watermark_is_relaxed_backlog "${sanitized}"; then
          printf 'relaxed_watermark=PASS local=%s remote=%s\n' "${local_mark}" "${remote_mark}"
          return 0
        fi
      fi
    fi
    (( $(date +%s) < deadline )) || {
      echo "BLOCKED: no pre-action Relaxed R<L watermark was observable for ${CURRENT_CAT}" >&2
      return 6
    }
    sleep 0.25
  done
}

dispatch_workflow() {
  local output url run_id source_generation expected_generation operation_kind
  CURRENT_WORKFLOW_RUN=""
  source_generation="$(jq -r '.generation' "${CURRENT_CASE_DIR}/cat-source.json")"
  expected_generation="$((source_generation + 1))"
  operation_kind="$(scenario_operation_kind "${CURRENT_SCENARIO}")"
  COORDINATION_TOKEN="q124-${RUN_ID}-${CURRENT_DURABILITY:0:1}-${CURRENT_SCENARIO}-r$(printf '%02d' "${CURRENT_ROUND}")"
  [[ "${COORDINATION_TOKEN}" =~ ^q124-[a-z0-9-]{8,75}$ ]]
  WORKFLOW_DISPATCHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  output="$(gh workflow run "${HA_WORKFLOW}" --ref main \
    -f mode=disrupt \
    -f confirmation=DELETE_ONE_CATS_CONTROLD_LEADER \
    -f coordination_mode=LOCK_Q124_LIFECYCLE \
    -f coordination_issue=124 \
    -f coordination_token="${COORDINATION_TOKEN}" \
    -f coordination_workspace_id="${WORKSPACE_ID}" \
    -f coordination_cat_id="${CURRENT_CAT_ID}" \
    -f coordination_cat_name="${CURRENT_CAT}" \
    -f coordination_generation="${expected_generation}" \
    -f coordination_operation_kind="${operation_kind}" \
    -f coordination_desired_state="$(scenario_target "${CURRENT_SCENARIO}")" \
    -f coordination_transitional_state="$(scenario_transition "${CURRENT_SCENARIO}")" \
    -f coordination_final_state="$(scenario_target "${CURRENT_SCENARIO}")")"
  printf '%s\n' "${output}" >"${CURRENT_CASE_DIR}/workflow-dispatch.log"
  url="$(printf '%s\n' "${output}" | awk '/^https:\/\/github.com\/.+\/actions\/runs\/[0-9]+\/?$/ {u=$0} END{print u}')"
  [[ "${url}" =~ /actions/runs/([1-9][0-9]*)/?$ ]] || {
    echo "workflow dispatch did not return an exact Actions run URL" >&2
    return 1
  }
  run_id="${BASH_REMATCH[1]}"
  CURRENT_WORKFLOW_RUN="${run_id}"
}

wait_coordination_ready() {
  local run_id="$1" deadline view status comments expected count
  expected="CATS_HA_COORD_READY token=${COORDINATION_TOKEN} run_id=${run_id} cat=${CURRENT_CAT_ID} generation=$(( $(jq -r '.generation' "${CURRENT_CASE_DIR}/cat-source.json") + 1 ))"
  deadline="$(( $(date +%s) + 180 ))"
  while true; do
    assert_guard_ok || return 1
    if view="$(gh run view "${run_id}" --json headSha,event,name,status,conclusion,url 2>&1)"; then
      printf '%s\n' "${view}" >"${CURRENT_CASE_DIR}/workflow-before-coordination.json"
      printf '%s' "${view}" | jq -e --arg sha "${SUT_RELEASE_SHA}" '
        .headSha == $sha and .event == "workflow_dispatch"
        and .name == "Verify production control-plane HA"
      ' >/dev/null
      status="$(printf '%s' "${view}" | jq -r '.status')"
      if [[ "${status}" == completed ]]; then
        echo "HA workflow completed before the lifecycle coordinator became ready" >&2
        return 1
      fi
    else
      printf '%s\n' "${view}" >>"${CURRENT_CASE_DIR}/workflow-view-errors.log"
    fi
    if comments="$(gh api --method GET "repos/${GITHUB_REPOSITORY}/issues/124/comments" \
      -f since="${WORKFLOW_DISPATCHED_AT}" -f per_page=100 2>&1)"; then
      count="$(printf '%s' "${comments}" | jq --arg expected "${expected}" '
        [.[] | select(.body == $expected and .user.login == "github-actions[bot]")] | length
      ')"
      if [[ "${count}" -eq 1 ]]; then
        printf '%s' "${comments}" | jq --arg expected "${expected}" '
          .[] | select(.body == $expected and .user.login == "github-actions[bot]")
          | {id,created_at,user:.user.login,body}
        ' >"${CURRENT_CASE_DIR}/coordination-ready-comment.json"
        return 0
      elif [[ "${count}" -gt 1 ]]; then
        echo "multiple exact coordination READY comments were observed" >&2
        return 1
      fi
    else
      printf '%s\n' "${comments}" >>"${CURRENT_CASE_DIR}/coordination-comment-errors.log"
    fi
    (( $(date +%s) < deadline )) || return 124
    sleep 0.5
  done
}

wait_workflow_terminal() {
  local run_id="$1" deadline view status conclusion
  deadline="$(( $(date +%s) + WORKFLOW_TIMEOUT_SECONDS ))"
  while true; do
    if view="$(gh run view "${run_id}" --json headSha,event,name,status,conclusion,jobs,url 2>&1)"; then
      printf '%s\n' "${view}" >"${CURRENT_CASE_DIR}/workflow-final.json"
      status="$(printf '%s' "${view}" | jq -r '.status')"
      if [[ "${status}" == completed ]]; then
        conclusion="$(printf '%s' "${view}" | jq -r '.conclusion')"
        [[ "${conclusion}" == success ]] || {
          gh run view "${run_id}" --log >"${CURRENT_CASE_DIR}/workflow.log" 2>&1 || true
          echo "HA workflow ${run_id} completed with ${conclusion}" >&2
          return 1
        }
        printf '%s' "${view}" | jq -e --arg sha "${SUT_RELEASE_SHA}" '
          .headSha == $sha and .event == "workflow_dispatch"
          and .name == "Verify production control-plane HA"
        ' >/dev/null || return 1
        gh run view "${run_id}" --log >"${CURRENT_CASE_DIR}/workflow.log"
        return 0
      fi
    else
      printf '%s\n' "${view}" >>"${CURRENT_CASE_DIR}/workflow-view-errors.log"
    fi
    (( $(date +%s) < deadline )) || return 124
    sleep 2
  done
}

poll_transition() {
  local desired="$1" transitional="$2" deadline cat_file operation_file
  cat_file="${CURRENT_CASE_DIR}/cat-transition.json"
  operation_file="${CURRENT_CASE_DIR}/operation-transition.json"
  deadline="$(( $(date +%s) + TRANSITION_TIMEOUT_SECONDS ))"
  : >"${CURRENT_CASE_DIR}/transition-poll.ndjson"
  while true; do
    assert_guard_ok || return 1
    if cats_json get "${CURRENT_CAT}" >"${cat_file}.next" 2>"${CURRENT_CASE_DIR}/transition-cat-errors.log" \
      && cats_json operation get "${CURRENT_OPERATION}" >"${operation_file}.next" 2>"${CURRENT_CASE_DIR}/transition-operation-errors.log"; then
      mv "${cat_file}.next" "${cat_file}"
      mv "${operation_file}.next" "${operation_file}"
      jq -cn --arg observed_at "$(date -u +%FT%TZ)" \
        --slurpfile cat "${cat_file}" --slurpfile operation "${operation_file}" \
        '{observed_at:$observed_at,cat:$cat[0],operation:$operation[0]}' \
        >>"${CURRENT_CASE_DIR}/transition-poll.ndjson"
      if transition_matches "${cat_file}" "${operation_file}" "${desired}" "${transitional}"; then
        date +%s >"${CURRENT_CASE_DIR}/transition-unix.txt"
        cats_json endpoint ls "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/route-transition.json"
        return 0
      fi
      if jq -e '.phase == "succeeded" or .phase == "failed"' "${operation_file}" >/dev/null; then
        echo "operation became terminal before ${transitional} was captured" >&2
        return 1
      fi
    fi
    (( $(date +%s) < deadline )) || {
      echo "did not capture ${transitional} with the original active operation" >&2
      return 124
    }
    sleep 0.1
  done
}

verify_workflow_oracles() {
  local operation_file="$1" transition_unix="$2" log_file
  local old_line new_line probe_line locked_line deletion_line release_line converged_line
  local handoff_iso handoff_epoch locked_iso locked_epoch_ms handoff_epoch_ms released_iso released_epoch_ms
  local old_leader new_leader locked_operation deleted_operation released_operation converged_operation
  local created updated
  log_file="${CURRENT_CASE_DIR}/workflow.log"
  old_line="$(awk 'index($0,"Reconciler leader before disruption:") && !index($0,"echo \"") {line=$0;n++} END{if(n==1)print line}' "${log_file}")"
  new_line="$(awk 'index($0,"Reconciler leader after disruption:") && !index($0,"echo \"") {line=$0;n++} END{if(n==1)print line}' "${log_file}")"
  probe_line="$(awk 'index($0,"All 240 public health probes succeeded") && !index($0,"echo \"") {line=$0;n++} END{if(n==1)print line}' "${log_file}")"
  locked_line="$(awk -v token="${COORDINATION_TOKEN}" 'index($0,"Lifecycle coordinator locked token=" token " ") && !index($0,"echo \"") {line=$0;n++} END{if(n==1)print line}' "${log_file}")"
  deletion_line="$(awk 'index($0,"Deleting lifecycle-locked leader:") && !index($0,"echo \"") {line=$0;n++} END{if(n==1)print line}' "${log_file}")"
  release_line="$(awk -v token="${COORDINATION_TOKEN}" 'index($0,"Lifecycle coordinator released token=" token " ") && !index($0,"echo \"") {line=$0;n++} END{if(n==1)print line}' "${log_file}")"
  converged_line="$(awk -v token="${COORDINATION_TOKEN}" 'index($0,"Lifecycle exact operation converged token=" token " ") && !index($0,"echo \"") {line=$0;n++} END{if(n==1)print line}' "${log_file}")"
  if [[ -z "${old_line}" || -z "${new_line}" || -z "${probe_line}" || -z "${locked_line}" \
     || -z "${deletion_line}" || -z "${release_line}" || -z "${converged_line}" ]]; then
    echo "workflow log lacks a unique leader, lock interval, exact convergence or 240-probe oracle" >&2
    return 1
  fi
  old_leader="$(sed -nE 's/.*Reconciler leader before disruption: ([^ ]+) .*/\1/p' <<<"${old_line}")"
  new_leader="$(sed -nE 's/.*Reconciler leader after disruption: ([^ ]+) .*/\1/p' <<<"${new_line}")"
  [[ -n "${old_leader}" && -n "${new_leader}" && "${old_leader}" != "${new_leader}" ]] || return 1
  locked_operation="$(sed -nE 's/.* operation=(op_[a-f0-9]+) locked_at=.*/\1/p' <<<"${locked_line}")"
  deleted_operation="$(sed -nE 's/.* operation=(op_[a-f0-9]+) deletion_at=.*/\1/p' <<<"${deletion_line}")"
  released_operation="$(sed -nE 's/.* operation=(op_[a-f0-9]+) released_at=.*/\1/p' <<<"${release_line}")"
  converged_operation="$(sed -nE 's/.* operation=(op_[a-f0-9]+) generation=.*/\1/p' <<<"${converged_line}")"
  [[ "${locked_operation}" == "${CURRENT_OPERATION}" && "${deleted_operation}" == "${CURRENT_OPERATION}" \
     && "${released_operation}" == "${CURRENT_OPERATION}" && "${converged_operation}" == "${CURRENT_OPERATION}" ]] || {
    echo "workflow did not lock, delete across, release and converge the original exact Operation" >&2
    return 1
  }
  locked_iso="$(sed -nE 's/.* locked_at=([^ ]+).*/\1/p' <<<"${locked_line}")"
  handoff_iso="$(sed -nE 's/.* deletion_at=([^ ]+).*/\1/p' <<<"${deletion_line}")"
  released_iso="$(sed -nE 's/.* released_at=([^ ]+).*/\1/p' <<<"${release_line}")"
  [[ -n "${locked_iso}" && -n "${handoff_iso}" && -n "${released_iso}" ]] || return 1
  locked_epoch_ms="$(iso_to_epoch_ms "${locked_iso}")"
  handoff_epoch="$(iso_to_epoch "${handoff_iso}")"
  handoff_epoch_ms="$(iso_to_epoch_ms "${handoff_iso}")"
  released_epoch_ms="$(iso_to_epoch_ms "${released_iso}")"
  (( locked_epoch_ms <= handoff_epoch_ms && handoff_epoch_ms <= released_epoch_ms )) || {
    printf 'lock_interval=FAIL locked=%s deletion=%s released=%s\n' \
      "${locked_iso}" "${handoff_iso}" "${released_iso}" >&2
    return 1
  }
  created="$(jq -r '.created_at_unix' "${operation_file}")"
  updated="$(jq -r '.updated_at_unix' "${operation_file}")"
  [[ "${created}" =~ ^[0-9]+$ && "${updated}" =~ ^[0-9]+$ ]] || return 1
  # Seconds are the finest precision exposed by Operation. The +1 tolerance is
  # only for that documented truncation, not a widened handoff window.
  (( transition_unix <= handoff_epoch + 1 \
     && created <= handoff_epoch + 1 \
     && handoff_epoch <= updated + 1 )) || {
    printf 'handoff_overlap=FAIL transition=%s op_created=%s handoff=%s op_updated=%s\n' \
      "${transition_unix}" "${created}" "${handoff_epoch}" "${updated}" >&2
    return 1
  }
  jq -n --arg old_leader "${old_leader}" --arg new_leader "${new_leader}" \
    --arg locked_at "${locked_iso}" --arg handoff_at "${handoff_iso}" --arg released_at "${released_iso}" \
    --arg operation_id "${CURRENT_OPERATION}" --argjson handoff_unix "${handoff_epoch}" \
    --argjson transition_unix "${transition_unix}" --argjson operation_created "${created}" \
    --argjson operation_updated "${updated}" \
    '{advisory_lock_owner_count_before:1,advisory_lock_owner_count_after:1,
      old_leader:$old_leader,new_leader:$new_leader,handoff_at:$handoff_at,
      lifecycle_lock_acquired_at:$locked_at,lifecycle_lock_released_at:$released_at,
      exact_operation_id:$operation_id,new_leader_exact_operation_converged:true,
      handoff_unix:$handoff_unix,transition_unix:$transition_unix,
      operation_created_unix:$operation_created,operation_updated_unix:$operation_updated,
      overlap:true,public_health_probes:240}' >"${CURRENT_CASE_DIR}/singleton-handoff-oracle.json"
  printf '%s\n' "${handoff_epoch}" >"${CURRENT_CASE_DIR}/handoff-unix.txt"
}

verify_original_operation() {
  local scenario="$1" final_cat="$2" operation_file="$3" operations_file kind generation source_generation
  kind="$(scenario_operation_kind "${scenario}")"
  generation="$(jq -r '.resource_generation' "${operation_file}")"
  source_generation="$(jq -r '.generation' "${CURRENT_CASE_DIR}/cat-source.json")"
  [[ "${source_generation}" =~ ^[0-9]+$ && "${generation}" =~ ^[0-9]+$ \
     && "${generation}" -eq $((source_generation + 1)) ]] || {
    printf 'generation_progression=FAIL source=%s operation=%s\n' \
      "${source_generation}" "${generation}" >&2
    return 1
  }
  jq -e --arg id "${CURRENT_OPERATION}" --arg resource "${CURRENT_CAT_ID}" \
    --arg kind "${kind}" --argjson generation "${generation}" '
    .id == $id and .resource_id == $resource and .kind == $kind
    and .resource_generation == $generation and .phase == "succeeded"
  ' "${operation_file}" >/dev/null
  jq -e --argjson generation "${generation}" '.generation == $generation' "${final_cat}" >/dev/null
  jq -e --argjson generation "${generation}" '.generation == $generation' \
    "${CURRENT_CASE_DIR}/cat-transition.json" >/dev/null

  operations_file="${CURRENT_CASE_DIR}/operation-list-after.json"
  cats_json operation ls >"${operations_file}"
  jq -e --arg id "${CURRENT_OPERATION}" --arg resource "${CURRENT_CAT_ID}" \
    --arg kind "${kind}" --argjson generation "${generation}" '
    type == "array"
    and ([.[] | select(.id == $id and .resource_id == $resource
          and .kind == $kind and .resource_generation == $generation)] | length) == 1
    and any(.[]; .id == $id and .phase == "succeeded")
  ' "${operations_file}" >/dev/null
}

verify_node_semantics() {
  local scenario="$1" source_node final_node
  source_node="$(jq -r '.node_id // empty' "${CURRENT_CASE_DIR}/cat-source.json")"
  final_node="$(jq -r '.node_id // empty' "${CURRENT_CASE_DIR}/cat-final.json")"
  case "${scenario}" in
    start)
      [[ -z "${source_node}" && "${final_node}" == "${REQUIRED_NODE_ID}" ]]
      ;;
    resume|restore|suspend|warm)
      [[ "${source_node}" == "${REQUIRED_NODE_ID}" && "${final_node}" == "${REQUIRED_NODE_ID}" ]]
      ;;
    stop)
      [[ "${source_node}" == "${REQUIRED_NODE_ID}" && -z "${final_node}" ]]
      ;;
  esac || {
    printf 'node_semantics=FAIL scenario=%s source_node=%s final_node=%s\n' \
      "${scenario}" "${source_node:-NULL}" "${final_node:-NULL}" >&2
    return 1
  }
  jq -n --arg scenario "${scenario}" --arg source_node "${source_node}" --arg final_node "${final_node}" \
    '{scenario:$scenario,source_node:(if $source_node == "" then null else $source_node end),
      final_node:(if $final_node == "" then null else $final_node end),semantics_valid:true}' \
    >"${CURRENT_CASE_DIR}/node-oracle.json"
}

verify_guest_identity() {
  local scenario="$1" pre post pre_counter post_counter pre_boot post_boot
  pre="${CURRENT_CASE_DIR}/guest-before.tsv"
  post="${CURRENT_CASE_DIR}/guest-after.tsv"
  pre_counter="$(awk -F '\t' '$1=="counter"{print $2}' "${pre}")"
  post_counter="$(awk -F '\t' '$1=="counter"{print $2}' "${post}")"
  pre_boot="$(awk -F '\t' '$1=="boot"{print $2}' "${pre}")"
  post_boot="$(awk -F '\t' '$1=="boot"{print $2}' "${post}")"
  [[ "${pre_counter}" =~ ^[0-9]+$ && "${post_counter}" =~ ^[0-9]+$ \
     && "${post_counter}" -gt "${pre_counter}" ]] || return 1
  case "${scenario}" in
    start|stop) [[ "${pre_boot}" != "${post_boot}" ]] ;;
    resume|restore|suspend|warm) [[ "${pre_boot}" == "${post_boot}" ]] ;;
  esac
  jq -n --arg scenario "${scenario}" --arg pre_boot "${pre_boot}" --arg post_boot "${post_boot}" \
    --arg pre_digest "$(awk -F '\t' '$1=="digest"{print $2}' "${pre}")" \
    --arg post_digest "$(awk -F '\t' '$1=="digest"{print $2}' "${post}")" \
    --argjson pre_counter "${pre_counter}" --argjson post_counter "${post_counter}" \
    '{scenario:$scenario,boot_before:$pre_boot,boot_after:$post_boot,
      digest_before:$pre_digest,digest_after:$post_digest,
      counter_before:$pre_counter,counter_after:$post_counter,guest_io_continued:true}' \
    >"${CURRENT_CASE_DIR}/guest-oracle.json"
}

verify_route_epochs() {
  local created_epoch final_epoch post_epoch
  created_epoch="$(awk -F '\t' '$2=="created" && $4=="200" {value=$6} END{print value}' \
    "${CURRENT_CASE_DIR}/route-probes.tsv")"
  final_epoch="$(awk -F '\t' '$2=="final" && $4=="200" {value=$6} END{print value}' \
    "${CURRENT_CASE_DIR}/route-probes.tsv")"
  post_epoch="$(awk -F '\t' '$2=="post-sentinel" && $4=="200" {value=$6} END{print value}' \
    "${CURRENT_CASE_DIR}/route-probes.tsv")"
  [[ "${created_epoch}" =~ ^[0-9]+$ && "${post_epoch}" =~ ^[0-9]+$ \
     && "${post_epoch}" -gt "${created_epoch}" ]] || {
    printf 'route_epoch=FAIL created=%s post=%s\n' "${created_epoch:-NULL}" "${post_epoch:-NULL}" >&2
    return 1
  }
  if [[ -n "${final_epoch}" && "${final_epoch}" != "${post_epoch}" ]]; then
    printf 'route_epoch=FAIL final_running=%s post=%s\n' "${final_epoch}" "${post_epoch}" >&2
    return 1
  fi
  jq -n --argjson created "${created_epoch}" --argjson post "${post_epoch}" \
    --arg final "${final_epoch}" \
    '{created_epoch:$created,final_running_epoch:(if $final == "" then null else ($final|tonumber) end),
      post_sentinel_epoch:$post,republished:($post > $created)}' \
    >"${CURRENT_CASE_DIR}/route-epoch-oracle.json"
}

record_current_cat_for_cleanup() {
  local value create_file
  [[ -n "${CURRENT_CAT}" && -n "${CURRENT_CASE_DIR}" && -z "${CURRENT_CAT_ID}" ]] || return 0
  create_file="${CURRENT_CASE_DIR}/create.log"
  if [[ -s "${create_file}" ]] && jq -e --arg name "${CURRENT_CAT}" --arg workspace "${WORKSPACE_ID}" '
      .name == $name and .workspace_id == $workspace
      and (.id | type == "string" and startswith("cat_"))
    ' "${create_file}" >/dev/null 2>&1; then
    CURRENT_CAT_ID="$(jq -r '.id' "${create_file}")"
    printf '%s\t%s\t%s\n' "${CURRENT_CAT}" "${CURRENT_CAT_ID}" "${CURRENT_CASE_DIR}" >>"${OWNED_TSV}"
    printf 'cleanup_ownership_rescue=PASS cat=%s id=%s\n' "${CURRENT_CAT}" "${CURRENT_CAT_ID}"
    return 0
  fi
  if value="$(cats_json get "${CURRENT_CAT}" 2>&1)"; then
    # A name appearing without a successful create response is not enough to
    # prove ownership: another q124 run could have won the precreate race.
    # Preserve it, leave the Node Cordoned, and require operator review.
    printf '%s\n' "${value}" >"${CURRENT_CASE_DIR}/cleanup-unproven-cat.json"
    echo "refusing to delete Cat without an exact successful create response: ${CURRENT_CAT}" >&2
    return 1
  fi
  printf '%s\n' "${value}" >"${CURRENT_CASE_DIR}/cleanup-rescue-not-found.log"
  [[ "${value}" == *"not found (NotFound)"* ]]
}

cleanup_one() {
  local cat_name="$1" cat_id="$2" case_dir="$3" before after
  FAILURE_DOMAIN=cleanup
  if before="$(cats_json get "${cat_name}" 2>&1)"; then
    printf '%s\n' "${before}" >"${case_dir}/cleanup-positive.json"
    printf '%s' "${before}" | jq -e --arg id "${cat_id}" --arg name "${cat_name}" \
      --arg workspace "${WORKSPACE_ID}" '
      .id == $id and .name == $name and .workspace_id == $workspace
    ' >/dev/null
    cats_json destroy "${cat_name}" >"${case_dir}/cleanup-destroy.log"
    if after="$(cats_json get "${cat_name}" 2>&1)"; then
      printf '%s\n' "${after}" >"${case_dir}/cleanup-unexpected-positive.json"
      echo "cleanup failed: ${cat_name} still resolves" >&2
      return 1
    fi
    printf '%s\n' "${after}" >"${case_dir}/cleanup-not-found.log"
    [[ "${after}" == *"not found (NotFound)"* ]] || return 1
  elif [[ "${before}" == *"not found (NotFound)"* && -s "${case_dir}/cleanup-not-found.log" ]]; then
    printf '%s\n' "${before}" >"${case_dir}/cleanup-repeat-not-found.log"
  else
    printf '%s\n' "${before}" >"${case_dir}/cleanup-unclassified.log"
    return 1
  fi
  capture_node_empty_cordoned after-cleanup "${case_dir}" || return 1
  FAILURE_DOMAIN=functional
}

cleanup_all() {
  local cat_name cat_id case_dir cleanup_failed=0 listing
  while IFS=$'\t' read -r cat_name cat_id case_dir; do
    [[ -n "${cat_name}" ]] || continue
    cleanup_one "${cat_name}" "${cat_id}" "${case_dir}" || cleanup_failed=1
  done <"${OWNED_TSV}"
  listing="$(cats_json ls 2>"${RUN_DIR}/final-list-errors.log")" || return 1
  printf '%s\n' "${listing}" >"${RUN_DIR}/final-cats-list.json"
  printf '%s' "${listing}" | jq -e 'type == "array"' >/dev/null || return 1
  while IFS=$'\t' read -r cat_name cat_id case_dir; do
    [[ -n "${cat_name}" ]] || continue
    if printf '%s' "${listing}" | jq -e --arg id "${cat_id}" --arg name "${cat_name}" \
      'any(.[]; .id == $id or .name == $name)' >/dev/null; then
      echo "owned Cat remains after cleanup: ${cat_name}" >&2
      cleanup_failed=1
    fi
  done <"${OWNED_TSV}"
  capture_node_empty_cordoned final-cleanup "${RUN_DIR}" || cleanup_failed=1
  return "${cleanup_failed}"
}

finish() {
  local original_rc="$1" functional_rc cleanup_rc=0 overall_rc result
  trap - EXIT INT TERM
  set +e
  functional_rc="${original_rc}"
  if [[ "${FAILURE_DOMAIN}" == cleanup ]]; then
    cleanup_rc="${original_rc}"
    functional_rc=0
  fi
  # Safety restoration is the first finalizer action. NODE_UNCORDONED is set
  # before every uncordon request, so an ambiguous request failure is covered.
  cordon_required_node finalizer || cleanup_rc=1
  record_current_cat_for_cleanup || cleanup_rc=1
  if [[ -n "${CURRENT_WORKFLOW_RUN}" ]]; then
    wait_workflow_terminal "${CURRENT_WORKFLOW_RUN}" || {
      [[ "${functional_rc}" -ne 0 ]] || functional_rc=1
    }
  fi
  if [[ -n "${CURRENT_OPERATION}" && -n "${CURRENT_CASE_DIR}" ]]; then
    wait_operation_terminal "${CURRENT_OPERATION}" "${CURRENT_CASE_DIR}/operation-finalizer.json" || {
      [[ "${functional_rc}" -ne 0 ]] || functional_rc=1
    }
  fi
  stop_public_probe
  stop_guard_watch
  cleanup_all || cleanup_rc=$?
  overall_rc="${functional_rc}"
  [[ "${overall_rc}" -ne 0 || "${cleanup_rc}" -eq 0 ]] || overall_rc="${cleanup_rc}"
  result=PASS
  [[ "${functional_rc}" -eq 0 ]] || result=FAIL
  [[ "${functional_rc}" -ne 6 ]] || result=BLOCKED
  [[ "${cleanup_rc}" -eq 0 ]] || result=CLEANUP_FAIL
  printf 'functional_rc\tcleanup_rc\toverall_rc\tresult\n%s\t%s\t%s\t%s\n' \
    "${functional_rc}" "${cleanup_rc}" "${overall_rc}" "${result}" >"${RESULT_TSV}"
  printf 'result=%s functional_rc=%s cleanup_rc=%s overall_rc=%s evidence=%s\n' \
    "${result}" "${functional_rc}" "${cleanup_rc}" "${overall_rc}" "${RUN_DIR}"
  exit "${overall_rc}"
}
trap 'finish $?' EXIT
trap 'exit 130' INT TERM

run_case() {
  local round="$1" durability="$2" scenario="$3" source transitional target desired
  local action short generation resource_generation transition_unix handoff_unix route_hostname final_route_code

  short="${durability:0:1}"
  CURRENT_CAT="q124-ha-${RUN_ID}-${short}-${scenario}-r$(printf '%02d' "${round}")"
  CURRENT_CASE_DIR="${RUN_DIR}/cases/${durability}-${scenario}-r$(printf '%02d' "${round}")"
  CURRENT_CAT_ID=""
  CURRENT_OPERATION=""
  CURRENT_WORKFLOW_RUN=""
  CURRENT_SCENARIO="${scenario}"
  CURRENT_DURABILITY="${durability}"
  CURRENT_ROUND="${round}"
  mkdir -p "${CURRENT_CASE_DIR}"
  source="$(scenario_source "${scenario}")"
  transitional="$(scenario_transition "${scenario}")"
  target="$(scenario_target "${scenario}")"
  desired="${target}"
  printf 'case_start utc=%s round=%s durability=%s scenario=%s cat=%s source=%s transitional=%s target=%s\n' \
    "$(date -u +%FT%TZ)" "${round}" "${durability}" "${scenario}" "${CURRENT_CAT}" \
    "${source}" "${transitional}" "${target}"

  assert_guard_ok
  deployment_guard
  create_case_cat "${durability}"
  prepare_source_state "${scenario}"
  capture_node_for_cat_state source "${CURRENT_CASE_DIR}/cat-source.json"
  if [[ "${durability}" == relaxed && ("${scenario}" == resume || "${scenario}" == restore) ]]; then
    prove_relaxed_watermark
  fi

  start_public_probe "${CURRENT_CASE_DIR}/public-health.tsv"
  dispatch_workflow
  printf '%s\n' "${CURRENT_WORKFLOW_RUN}" >"${CURRENT_CASE_DIR}/workflow-run-id.txt"
  wait_coordination_ready "${CURRENT_WORKFLOW_RUN}"

  action="$(scenario_cli_action "${scenario}")"
  if [[ "${scenario}" == start ]]; then
    # Stop-to-Cold cleared placement. Re-open only until this exact generation
    # has durably claimed the required Node and entered Starting.
    capture_node_empty_cordoned before-lifecycle-start
    uncordon_required_node lifecycle-start
  fi
  submit_operation "${action}" "${CURRENT_CAT}" "${CURRENT_CASE_DIR}/operation-accepted.log"
  CURRENT_OPERATION="${SUBMITTED_OPERATION_ID}"
  printf '%s\n' "${CURRENT_OPERATION}" >"${CURRENT_CASE_DIR}/operation-id.txt"
  poll_transition "${desired}" "${transitional}"
  if [[ "${scenario}" == start ]]; then
    cordon_required_node after-lifecycle-start-claim
    capture_node_has_current_cat after-lifecycle-start-claim
  fi
  transition_unix="$(<"${CURRENT_CASE_DIR}/transition-unix.txt")"
  wait_operation_terminal "${CURRENT_OPERATION}" "${CURRENT_CASE_DIR}/operation-final.json"
  wait_workflow_terminal "${CURRENT_WORKFLOW_RUN}"

  cats_json get "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/cat-final.json"
  jq -e --arg desired "${desired}" --arg target "${target}" '
    .desired_state == $desired and .observed_state == $target
  ' "${CURRENT_CASE_DIR}/cat-final.json" >/dev/null
  capture_node_for_cat_state final "${CURRENT_CASE_DIR}/cat-final.json"
  cats_json endpoint ls "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/route-final.json"
  route_hostname="$(jq -r 'if length == 1 then .[0].hostname else empty end' "${CURRENT_CASE_DIR}/route-created.json")"
  [[ -n "${route_hostname}" ]]
  jq -e --arg hostname "${route_hostname}" 'length == 1 and .[0].hostname == $hostname' \
    "${CURRENT_CASE_DIR}/route-source.json" >/dev/null
  jq -e --arg hostname "${route_hostname}" 'length == 1 and .[0].hostname == $hostname' \
    "${CURRENT_CASE_DIR}/route-transition.json" >/dev/null
  jq -e --arg hostname "${route_hostname}" 'length == 1 and .[0].hostname == $hostname' \
    "${CURRENT_CASE_DIR}/route-final.json" >/dev/null
  final_route_code=503
  [[ "${target}" != running ]] || final_route_code=200
  probe_public_route final "${final_route_code}"

  verify_original_operation "${scenario}" "${CURRENT_CASE_DIR}/cat-final.json" \
    "${CURRENT_CASE_DIR}/operation-final.json"
  verify_node_semantics "${scenario}"
  verify_workflow_oracles "${CURRENT_CASE_DIR}/operation-final.json" "${transition_unix}"
  handoff_unix="$(<"${CURRENT_CASE_DIR}/handoff-unix.txt")"
  stop_public_probe
  assert_public_probe "${CURRENT_CASE_DIR}/public-health.tsv"
  deployment_guard

  # `exec` deliberately runs only after the original target state and route
  # have been captured. It wakes non-running targets so the persisted Guest I/O
  # sentinel, boot identity and digest can be checked without contaminating the
  # original Operation's generation oracle.
  if [[ "${scenario}" == stop ]]; then
    # The cold-restart identity oracle needs one new placement. Keep the Node
    # Ready only for this exact Cat's blocking exec/wake, then close it again.
    capture_node_empty_cordoned before-post-sentinel-wake
    uncordon_required_node post-sentinel-wake
    capture_guest_sentinel after
    cordon_required_node after-post-sentinel-wake
    cats_json get "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/cat-after-post-sentinel-wake.json"
    capture_node_for_cat_state post-sentinel-wake "${CURRENT_CASE_DIR}/cat-after-post-sentinel-wake.json"
  else
    capture_guest_sentinel after
  fi
  verify_guest_identity "${scenario}"
  cats_json get "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/cat-post-sentinel.json"
  cats_json endpoint ls "${CURRENT_CAT}" >"${CURRENT_CASE_DIR}/route-post-sentinel.json"
  probe_public_route post-sentinel 200
  verify_route_epochs

  generation="$(jq -r '.generation' "${CURRENT_CASE_DIR}/cat-final.json")"
  resource_generation="$(jq -r '.resource_generation' "${CURRENT_CASE_DIR}/operation-final.json")"
  cleanup_one "${CURRENT_CAT}" "${CURRENT_CAT_ID}" "${CURRENT_CASE_DIR}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tPASS\n' \
    "${round}" "${durability}" "${scenario}" "${CURRENT_CAT}" "${CURRENT_CAT_ID}" \
    "${generation}" "${CURRENT_OPERATION}" "${resource_generation}" "${transition_unix}" \
    "${handoff_unix}" "${CURRENT_WORKFLOW_RUN}" >>"${CASES_TSV}"
  CURRENT_CAT=""
  CURRENT_CAT_ID=""
  CURRENT_CASE_DIR=""
  CURRENT_OPERATION=""
  CURRENT_WORKFLOW_RUN=""
  printf 'case_result=PASS round=%s durability=%s scenario=%s\n' "${round}" "${durability}" "${scenario}"
}

printf 'started_at=%s harness_commit=%s workspace=%s workspace_id=%s required_node=%s run_id=%s rounds=%s durabilities=%s scenarios=%s sut_sha=%s deploy_run=%s workflow=%s\n' \
  "$(date -u +%FT%TZ)" "$(git rev-parse HEAD)" "${WORKSPACE}" "${WORKSPACE_ID}" "${REQUIRED_NODE_ID}" \
  "${RUN_ID}" "${ROUNDS}" "${DURABILITIES}" "${SCENARIOS}" "${SUT_RELEASE_SHA}" "${SUT_DEPLOY_RUN_ID}" "${HA_WORKFLOW}"
"${CATS_BIN}" --version
gh auth status >/dev/null
actual_repository="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
[[ "${actual_repository}" == "${GITHUB_REPOSITORY}" ]]
printf '{"nameWithOwner":"%s"}\n' "${actual_repository}" >"${RUN_DIR}/github-repository.json"
deployment_guard

# Bind the mutable workspace selector to the exact q124 workspace ID without
# retaining user profile fields in the qualification artifacts.
me="$(cats_json whoami)"
printf '%s' "${me}" | jq -e --arg id "${WORKSPACE_ID}" --arg selector "${WORKSPACE}" '
  [.workspaces[] | select(.id == $id and (.id == $selector or .locator == $selector))] | length == 1
' >/dev/null
printf '%s' "${me}" | jq --arg id "${WORKSPACE_ID}" '
  .workspaces[] | select(.id == $id) | {id,locator,account_id,slug}
' >"${RUN_DIR}/workspace-identity.json"

# The requested deploy run itself is a positive control for the later latest-
# deployment absence/identity guard.
gh run view "${SUT_DEPLOY_RUN_ID}" --json databaseId,name,status,conclusion,headSha,url \
  >"${RUN_DIR}/sut-deploy-run.json"
jq -e --argjson id "${SUT_DEPLOY_RUN_ID}" --arg sha "${SUT_RELEASE_SHA}" '
  .databaseId == $id and .name == "Deploy production" and .status == "completed"
  and .conclusion == "success" and .headSha == $sha
' "${RUN_DIR}/sut-deploy-run.json" >/dev/null

guard_watch &
GUARD_PID=$!

for durability in ${DURABILITIES}; do
  for scenario in ${SCENARIOS}; do
    for ((round = 1; round <= ROUNDS; round++)); do
      run_case "${round}" "${durability}" "${scenario}"
    done
  done
done

exit 0
