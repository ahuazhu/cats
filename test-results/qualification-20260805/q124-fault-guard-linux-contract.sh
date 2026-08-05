#!/usr/bin/env bash
set -euo pipefail
[[ "${EUID}" == 0 ]] || { echo 'run as root in a disposable Linux container' >&2; exit 2; }

SOURCE_GUARD="${1:-test-results/qualification-20260805/live-hooks/q124-fault-guard}"
ROOT="$(mktemp -d /tmp/q124-guard-contract.XXXXXX)"
BIN="${ROOT}/bin"; STATE="${ROOT}/state"; SHA=1111111111111111111111111111111111111111
ASSET_DIR="/opt/cats/qualification-124/${SHA}"
ETC_DIR=/etc/cats/qualification-124
GUARD="${ASSET_DIR}/q124-fault-guard"; HOOK="${ASSET_DIR}/q124-fault-workload"
mkdir -p "${BIN}" "${STATE}" "${ASSET_DIR}" "${ETC_DIR}"
trap 'rm -rf "${ROOT}" "${ASSET_DIR}" "${ETC_DIR}"' EXIT HUP INT TERM
cp "${SOURCE_GUARD}" "${GUARD}"

cat >"${HOOK}" <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"${MOCK_STATE}/hook.log"
HOOK
chmod 0700 "${GUARD}" "${HOOK}"
printf '%s\n' '{"schema_version":1}' >"${ETC_DIR}/fault-targets.json"
chmod 0600 "${ETC_DIR}/fault-targets.json"

write_manifest() {
  jq -n --arg sha "${SHA}" \
    --arg config "$(sha256sum "${ETC_DIR}/fault-targets.json" | awk '{print $1}')" \
    --arg guard "$(sha256sum "${GUARD}" | awk '{print $1}')" \
    --arg hook "$(sha256sum "${HOOK}" | awk '{print $1}')" '
    {schema_version:1,issue:124,test_sha:$sha,qualification_assets:{
      config_sha256:$config,guard_sha256:$guard,
      guard_repo_path:"test-results/qualification-20260805/live-hooks/q124-fault-guard",
      hook_sha256:$hook,
      hook_repo_path:"test-results/qualification-20260805/live-hooks/q124-fault-workload"}}
  ' >"${ETC_DIR}/provisioning-manifest.json"
  chmod 0600 "${ETC_DIR}/provisioning-manifest.json"
}
write_manifest

cat >"${BIN}/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
output= method=GET url=
while (($#)); do
  case "$1" in
    --output) shift; output="$1" ;;
    --request) shift; method="$1" ;;
    http*) url="$1" ;;
  esac
  shift
done
printf '%s\t%s\n' "${method}" "${url}" >>"${MOCK_STATE}/curl.log"
case "${url}" in
  */cats) printf '%s\n' '{"items":[]}' >"${output}" ;;
  *) printf '%s\n' '{"node":{"id":"q124-20260805000000-abcdef","state":"cordoned"},"assigned_cats":0,"orphan_cats":0}' >"${output}" ;;
esac
printf 200
MOCK

cat >"${BIN}/systemd-run" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
unit=; start=0; command=()
for arg in "$@"; do
  [[ "${arg}" != --unit ]] || { start=-1; continue; }
  if (( start == -1 )); then unit="${arg}"; start=0; continue; fi
  [[ "${arg}" != --unit=* ]] || unit="${arg#--unit=}"
  if [[ "${arg}" == /opt/cats/qualification-124/*/q124-fault-guard ]]; then start=1; fi
  (( start == 0 )) || command+=("${arg}")
done
touch "${MOCK_STATE}/${unit}.timer" "${MOCK_STATE}/watchdog-armed"
(
  sleep 1
  [[ -f "${MOCK_STATE}/${unit}.timer" ]] || exit 0
  "${command[@]}" >/dev/null 2>&1 || true
) </dev/null >/dev/null 2>&1 &
MOCK

cat >"${BIN}/systemctl" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  is-active) [[ -f "${MOCK_STATE}/${*: -1}" ]] ;;
  stop) rm -f "${MOCK_STATE}/$2" ;;
  reset-failed) exit 0 ;;
esac
MOCK
chmod 0700 "${BIN}"/*

run_guard() { env PATH="${BIN}:/usr/bin:/bin" MOCK_STATE="${STATE}" "$@" "${GUARD}" verify; }
expect_reject() {
  local name="$1"; shift
  set +e; "$@" >/dev/null 2>&1; rc=$?; set -e
  [[ "${rc}" -ne 0 ]] || { echo "negative unexpectedly passed: ${name}" >&2; exit 1; }
  printf '%s\tPASS\n' "${name}"
}

run_guard env
printf 'valid-root-assets\tPASS\n'

printf '%s\n' 'global-admin-token-must-be-rejected' >"${ETC_DIR}/admin-token"; chmod 0600 "${ETC_DIR}/admin-token"
expect_reject legacy-worker-admin-token run_guard env
rm -f "${ETC_DIR}/admin-token"

mv "${HOOK}" "${HOOK}.real"; ln -s "${HOOK}.real" "${HOOK}"
expect_reject symlink-hook run_guard env
rm "${HOOK}"; mv "${HOOK}.real" "${HOOK}"

chmod 0770 "${ASSET_DIR}"
expect_reject writable-ancestor run_guard env
chmod 0755 "${ASSET_DIR}"

chmod 0777 "${HOOK}"
expect_reject insecure-mode run_guard env
chmod 0700 "${HOOK}"

chown 1:1 "${HOOK}"
expect_reject non-root-owner run_guard env
chown 0:0 "${HOOK}"

printf '\n# mutation\n' >>"${HOOK}"
expect_reject sha-mismatch run_guard env
sed -i '$d' "${HOOK}"; sed -i '$d' "${HOOK}"
write_manifest

printf 'result=PASS guard_negatives=6\n'
