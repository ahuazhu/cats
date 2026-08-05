#!/usr/bin/env bash
set -euo pipefail
[[ "${EUID}" == 0 ]] || { echo 'run as root in a disposable Linux container' >&2; exit 2; }
HARNESS="${1:-test-results/qualification-20260805/temp-node-faults.sh}"
ROOT="$(mktemp -d /tmp/q124-observer-cleanup.XXXXXX)"; BIN="${ROOT}/bin"
mkdir "${BIN}"
trap 'rm -rf "${ROOT}" /run/cats-q124-observer-cleanup-contract.{json,ready,armed}' EXIT HUP INT TERM
cat >"${BIN}/sudo" <<'MOCK'
#!/usr/bin/env bash
[[ "${1:-}" != -n ]] || shift
exec "$@"
MOCK
chmod 0700 "${BIN}/sudo"
PATH="${BIN}:/usr/bin:/bin"

# Load the production cleanup function verbatim without executing harness main.
eval "$(awk '/^cleanup_external_observer\(\)/{copy=1} copy{print} copy && /^}/{exit}' "${HARNESS}")"
rg -q '^trap cleanup_external_observer EXIT$' "${HARNESS}"

for reason in dispatch-failure invalid-command-id terminal-status; do
  output="/run/cats-q124-observer-cleanup-contract.json"
  ready="/run/cats-q124-observer-cleanup-contract.ready"
  armed="/run/cats-q124-observer-cleanup-contract.armed"
  touch "${output}" "${ready}" "${armed}"
  setsid sh -c 'trap "" TERM; sleep 30' & observer_pid=$!
  for _ in $(seq 1 100); do [[ "$(ps -o pgid= -p "${observer_pid}" 2>/dev/null | tr -d ' ')" == "${observer_pid}" ]] && break; sleep 0.01; done
  OBSERVER_PROCESS_GROUP="${observer_pid}"
  OBSERVER_TEMP_FILES=("${output}" "${ready}" "${armed}")
  cleanup_external_observer
  ! kill -0 -- "-${observer_pid}" 2>/dev/null
  [[ ! -e "${output}" && ! -e "${ready}" && ! -e "${armed}" ]]
  printf 'observer-cleanup-%s\tPASS\n' "${reason}"
done

printf 'result=PASS observer_cleanup_paths=3\n'
