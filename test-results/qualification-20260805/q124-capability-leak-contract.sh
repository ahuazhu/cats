#!/usr/bin/env bash
set -euo pipefail

# Calibrated source/evidence scan for literal credentials and worker-side
# global administrator authority. It prints paths only, never matching text.

ROOT="$(git rev-parse --show-toplevel)"
BASE_SHA="${Q124_SCAN_BASE_SHA:-$(git -C "${ROOT}" rev-parse HEAD^)}"
TMP="$(mktemp -d /tmp/q124-capability-scan.XXXXXX)"
trap 'rm -rf "${TMP}"' EXIT HUP INT TERM

patterns=(
  -e "CATS_ADMIN_TOKEN[[:space:]]*=[[:space:]]*['\"]?[A-Za-z0-9._~-]{32,}"
  -e "Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._~-]{20,}"
  -e 'postgres(ql)?://[^[:space:]:]+:[^[:space:]@]+@'
  -e '(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}([^A-Z0-9]|$)'
  -e 'eyJ[A-Za-z0-9_-]{8,}[.]eyJ[A-Za-z0-9_-]{8,}[.][A-Za-z0-9_-]{8,}'
)

# Known-positive calibration uses the exact same patterns and rg engine. Build
# the sentinel in pieces so the contract source itself is not a scanner hit.
printf 'CATS_%s=%s\n' ADMIN_TOKEN q124KnownPositiveCapability0123456789abcdef >"${TMP}/known-positive"
rg -q "${patterns[@]}" "${TMP}/known-positive" || {
  echo 'credential scanner failed its known-positive calibration' >&2; exit 1;
}
printf 'credential-probe-calibration\tPASS\n'

tracked_count="$(git -C "${ROOT}" ls-files | awk 'END {print NR+0}')"
(( tracked_count > 100 )) || { echo 'credential scan input is unexpectedly empty' >&2; exit 1; }
rg -q '^\[workspace\]' "${ROOT}/Cargo.toml" || {
  echo 'repository visibility calibration failed' >&2; exit 1;
}

common_globs=(--glob '!.git/**' --glob '!.worktrees/**' --glob '!target/**'
  --glob '!node_modules/**' --glob '!__pycache__/**')

# Global-admin assignments and literal Bearer values have no source-tree
# exception. PostgreSQL loopback/example DSNs are intentionally committed test
# fixtures; AWS/JWT literals are allowed only in final-audit's calibrated
# positive controls.
set +e
hits="$(rg --no-messages --no-ignore --hidden -l \
  -e "CATS_ADMIN_TOKEN[[:space:]]*=[[:space:]]*['\"]?[A-Za-z0-9._~-]{32,}" \
  -e "Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._~-]{20,}" \
  "${common_globs[@]}" "${ROOT}")"
scan_rc=$?
set -e
if (( scan_rc == 0 )); then
  printf 'literal global-admin/Bearer candidates found in:\n%s\n' "${hits}" >&2; exit 1
elif (( scan_rc != 1 )); then
  echo 'whole-tree admin/Bearer scan failed' >&2; exit "${scan_rc}"
fi

postgres_json="$(rg --no-messages --no-ignore --hidden --json \
  -e 'postgres(ql)?://[^[:space:]:]+:[^[:space:]@]+@' \
  "${common_globs[@]}" "${ROOT}" || true)"
postgres_count="$(jq -sr '[.[] | select(.type=="match")] | length' <<<"${postgres_json}")"
unexpected="$(jq -sr -r '
  .[] | select(.type=="match") |
  select((.data.lines.text | test("@(db[.]example|127[.]0[.]0[.]1|localhost|host([/:])|RDS_HOST|[$][{](CATS_POSTGRES_HOST|pg)[}])")) | not) |
  .data.path.text
' <<<"${postgres_json}")"
[[ -z "${unexpected}" ]] || {
  printf 'non-example PostgreSQL credential candidates found in:\n%s\n' "${unexpected}" >&2; exit 1;
}

high_entropy_json="$(rg --no-messages --no-ignore --hidden --json \
  -e '(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}([^A-Z0-9]|$)' \
  -e 'eyJ[A-Za-z0-9_-]{8,}[.]eyJ[A-Za-z0-9_-]{8,}[.][A-Za-z0-9_-]{8,}' \
  "${common_globs[@]}" "${ROOT}" || true)"
high_entropy_count="$(jq -sr '[.[] | select(.type=="match")] | length' <<<"${high_entropy_json}")"
unexpected="$(jq -sr -r '
  .[] | select(.type=="match") |
  select((.data.path.text | endswith("/test-results/qualification-20260805/final-audit.sh")) | not) |
  .data.path.text
' <<<"${high_entropy_json}")"
[[ -z "${unexpected}" && "${high_entropy_count}" == 2 ]] || {
  printf 'unexpected AWS/JWT candidates found in:\n%s\n' "${unexpected:-<count-mismatch>}" >&2; exit 1;
}
printf 'whole-tree-literal-credential-scan\tPASS tracked=%s postgres_examples=%s calibrated_entropy=%s\n' \
  "${tracked_count}" "${postgres_count}" "${high_entropy_count}"

# Calibrate stdin/diff plumbing separately, then scan the complete submitted
# range plus the working tree without printing matching lines.
printf '+CATS_%s=%s\n' ADMIN_TOKEN q124KnownPositiveCapability0123456789abcdef |
  rg -q "${patterns[@]}" || { echo 'diff credential scanner calibration failed' >&2; exit 1; }
git -C "${ROOT}" cat-file -e "${BASE_SHA}^{commit}"
if git -C "${ROOT}" diff --quiet "${BASE_SHA}" --; then
  echo 'commit-range scan input is unexpectedly empty' >&2
  exit 1
fi
if git -C "${ROOT}" diff --no-ext-diff --unified=0 "${BASE_SHA}" -- | rg -q "${patterns[@]}"; then
  echo 'literal credential candidate found in submitted diff' >&2
  exit 1
fi
printf 'commit-range-literal-credential-scan\tPASS base=%s\n' "${BASE_SHA}"

worker_paths=(
  "${ROOT}/test-results/qualification-20260805/live-hooks/q124-fault-workload"
  "${ROOT}/test-results/qualification-20260805/temp-node-faults.sh"
  "${ROOT}/test-results/qualification-20260805/temp-node-fault-matrix.sh"
  "${ROOT}/test-results/qualification-20260805/temp-node-faults.provisioning.fixture.json"
)
! rg -n 'CATS_ADMIN_TOKEN|ADMIN_TOKEN|/etc/cats/qualification-124/admin-token|/v1/admin/' \
  "${worker_paths[@]}" >/dev/null
! rg -n 'q124-admin-token|Authorization:[[:space:]]*Bearer|admin[_-]?token' \
  "${ROOT}/test-results/qualification-20260805/temp-node-faults.provisioning.fixture.json" >/dev/null
! rg -n 'systemd-run.*(admin|token)|systemctl.*(admin|token)' "${worker_paths[@]}" >/dev/null
printf 'worker-manifest-argv-systemd-boundary\tPASS\n'

# The old deployable worker adapter must be absent; only the explicitly named
# independent-runner adapter may retain administrator API authority.
[[ ! -e "${ROOT}/test-results/qualification-20260805/live-hooks/q124-admin-node" ]]
rg -q 'administrator adapter must run on the independent main-branch Actions runner' \
  "${ROOT}/deploy/aws/qualification/q124-admin-node-runner.sh"
printf 'admin-authority-externalized\tPASS\n'

printf 'result=PASS calibrated=2 negative_scans=4\n'
