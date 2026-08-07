#!/usr/bin/env bash
set -euo pipefail

readonly source_dir="/srv/cats-build/source"
readonly target_parent="/srv/cats-build/target"
readonly build_receipt_dir="/var/lib/cats-build/build-receipts"
readonly receipt_library="/usr/local/lib/cats-build/immutable-receipt.sh"
readonly lock_file="/run/lock/cats-source-delivery.lock"
# shellcheck source=/dev/null
source "${receipt_library}"

install -d -m 0755 -o root -g root /run/lock
exec 9>"${lock_file}"
flock -x 9

if [[ "$(id -u)" != "0" ]]; then
  echo "cats-run-build is a trusted root orchestrator" >&2
  exit 77
fi
if [[ $# -lt 5 || ! $1 =~ ^[0-9a-f]{40}$ || ! $2 =~ ^[0-9a-f]{64}$ || ! $3 =~ ^[0-9a-f]{64}$ ]]; then
  echo "usage: cats-run-build <40hex-commit> <64hex-manifest-sha256> <64hex-bundle-sha256> [--with-postgres] -- <command> [args...]" >&2
  exit 64
fi
readonly source_sha="$1"
readonly manifest_sha256="$2"
readonly bundle_sha256="$3"
with_postgres=false
if [[ $4 == "--with-postgres" ]]; then
  with_postgres=true
  if [[ $# -lt 6 || $5 != "--" ]]; then
    echo "--with-postgres must be followed by -- and a command" >&2
    exit 64
  fi
  shift 5
elif [[ $4 == "--" ]]; then
  shift 4
else
  echo "expected --with-postgres or --" >&2
  exit 64
fi
readonly receipt="/var/lib/cats-build/source-receipts/${source_sha}-${manifest_sha256}.json"
readonly active_delivery="${source_dir}/.git/cats-active-delivery-v1.json"
readonly target_base="${target_parent}/${source_sha}-${manifest_sha256}-${bundle_sha256}"

if [[ ! -d "${source_dir}/.git" ]]; then
  echo "exact source must be delivered before a build" >&2
  exit 65
fi
readonly resolved_sha="$(
  env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/run/cats-build-root-git \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    -C "${source_dir}" rev-parse HEAD
)"
if [[ "${resolved_sha}" != "${source_sha}" ]]; then
  echo "published source is not the requested exact commit" >&2
  exit 65
fi
for immutable_file in "${receipt}" "${active_delivery}"; do
  if [[ ! -f "${immutable_file}" || -L "${immutable_file}" || "$(stat --format='%u:%a' "${immutable_file}")" != "0:444" ]]; then
    echo "active source provenance is not root-owned immutable data" >&2
    exit 65
  fi
done
readonly tree_sha="$(
  env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/run/cats-build-root-git \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    -C "${source_dir}" rev-parse 'HEAD^{tree}'
)"
jq -e \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  '.source_sha == $source_sha and .tree_sha == $tree_sha and
   .manifest_sha256 == $manifest_sha256 and .bundle_sha256 == $bundle_sha256 and
   .source_owner == "root" and .source_writable_by_build == false' \
  "${receipt}" >/dev/null
jq -e \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  'keys == ["bundle_sha256", "manifest_sha256", "schema_version", "source_sha", "tree_sha"] and
   .schema_version == 1 and .source_sha == $source_sha and .tree_sha == $tree_sha and
   .manifest_sha256 == $manifest_sha256 and .bundle_sha256 == $bundle_sha256' \
  "${active_delivery}" >/dev/null

install -d -m 0755 -o root -g root "${target_base}"
readonly job_dir="$(mktemp -d "${target_base}/job.XXXXXX")"
readonly job_id="$(basename -- "${job_dir}")"
chown cats-build:cats-build "${job_dir}"
install -d -m 0755 -o cats-build -g cats-build \
  "${job_dir}/home" "${job_dir}/cargo-home" "${job_dir}/cargo-target" "${job_dir}/output"

postgres_url=""
postgres_name=""
cleanup() {
  if [[ -n "${postgres_name}" ]]; then
    docker rm -f "${postgres_name}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM
if [[ "${with_postgres}" == "true" ]]; then
  readonly postgres_image="$(jq -er '.container_images.postgres_16_linux_amd64' /opt/cats-build/toolchain-lock-v1.json)"
  postgres_name="cats-build-pg-${source_sha:0:12}-$$"
  docker run --rm -d \
    --name "${postgres_name}" \
    --network bridge \
    --publish 127.0.0.1::5432 \
    --env POSTGRES_PASSWORD=cats \
    "${postgres_image}" >/dev/null
  postgres_port=""
  for _ in $(seq 1 120); do
    if docker exec "${postgres_name}" pg_isready -U postgres >/dev/null 2>&1; then
      postgres_port="$(docker port "${postgres_name}" 5432/tcp | head -1 | awk -F: '{print $NF}')"
      [[ -z "${postgres_port}" ]] || break
    fi
    sleep 0.5
  done
  if [[ -z "${postgres_port}" ]]; then
    echo "trusted PostgreSQL service did not become ready" >&2
    exit 74
  fi
  postgres_url="postgres://postgres:cats@127.0.0.1:${postgres_port}/postgres"
fi

build_environment=(
  HOME="${job_dir}/home"
  USER=cats-build
  LOGNAME=cats-build
  PATH=/opt/cats-build/cargo/bin:/usr/local/bin:/usr/bin:/bin
  CARGO_HOME="${job_dir}/cargo-home"
  RUSTUP_HOME=/opt/cats-build/rustup
  CARGO_TARGET_DIR="${job_dir}/cargo-target"
  CATS_BUILD_OUTPUT_DIR="${job_dir}/output"
  GIT_CONFIG_NOSYSTEM=1
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_TERMINAL_PROMPT=0
)
if [[ -n "${postgres_url}" ]]; then
  build_environment+=(CATS_TEST_POSTGRES_URL="${postgres_url}")
fi
status=0
readonly systemd_unit="cats-build-${job_id//./-}"
systemd-run --quiet --wait --collect --pipe \
  --unit "${systemd_unit}" \
  --service-type=exec \
  --uid=cats-build \
  --gid=cats-build \
  --property=KillMode=control-group \
  --property=SendSIGKILL=yes \
  --property=ProtectHome=true \
  --property=PrivateTmp=true \
  --property=PrivateIPC=true \
  --property=NoNewPrivileges=true \
  /usr/bin/env -i "${build_environment[@]}" \
  bash -c 'cd /srv/cats-build/source && exec "$@"' cats-run-build "$@" || status=$?

chown -R root:root "${job_dir}/output"
find -P "${job_dir}/output" -xdev -type d -exec chmod 0555 {} +
find -P "${job_dir}/output" -xdev -type f -exec chmod 0444 {} +
chown root:root "${job_dir}"
chmod 0555 "${job_dir}"
install -d -m 0755 -o root -g root "${build_receipt_dir}"
readonly prepared_build_receipt="$(mktemp "${build_receipt_dir}/.${job_id}.XXXXXX")"
readonly build_receipt_path="${build_receipt_dir}/${job_id}.json"
readonly command_json="$(printf '%s\0' "$@" | jq -Rs 'split("\u0000")[:-1]')"
jq -n -S \
  --arg source_sha "${source_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  --arg tree_sha "${tree_sha}" \
  --arg job_id "${job_id}" \
  --arg job_dir "${job_dir}" \
  --arg output_dir "${job_dir}/output" \
  --arg source_receipt "${receipt}" \
  --arg bootstrap_payload_sha256 "$(jq -er '.bootstrap_payload_sha256' /etc/cats-build/identity.json)" \
  --argjson command "${command_json}" \
  --argjson exit_status "${status}" \
  --argjson with_postgres "${with_postgres}" \
  '{schema_version: 1, source_sha: $source_sha, tree_sha: $tree_sha, manifest_sha256: $manifest_sha256, bundle_sha256: $bundle_sha256, job_id: $job_id, job_dir: $job_dir, output_dir: $output_dir, source_receipt: $source_receipt, command: $command, with_postgres: $with_postgres, exit_status: $exit_status, bootstrap_payload_sha256: $bootstrap_payload_sha256, aws_environment_forwarded: false, reusable_home: false, job_cgroup_drained: true, output_frozen: true}' \
  >"${prepared_build_receipt}"
write_immutable_receipt "${prepared_build_receipt}" "${build_receipt_path}"
chown root:root "${build_receipt_path}"
printf 'build receipt: %s\n' "${build_receipt_path}"
exit "${status}"
