#!/usr/bin/env bash
# Prepare, verify, or run the trusted root-only native manual-release lane.
set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
usage: manual-release-host.sh <prepare|verify|build> <40hex-commit> <64hex-manifest-sha256> <64hex-bundle-sha256> <control-repository:tag> <credential-refresher-repository:tag> <gateway-repository:tag>

The exact source must already have been delivered by cats-checkout-exact-sha.
prepare installs only the version-locked Guest/buildx/Rust prerequisites.
verify is read-only. build produces a frozen --export-images release and the
ordinary qualification build receipt; it never pushes or logs in to a registry.
EOF
}

if [[ $# -ne 7 || ! $2 =~ ^[0-9a-f]{40}$ || ! $3 =~ ^[0-9a-f]{64}$ || ! $4 =~ ^[0-9a-f]{64}$ ]]; then
  usage
  exit 64
fi
case "$1" in
  prepare|verify|build) readonly operation="$1" ;;
  *) usage; exit 64 ;;
esac
if [[ $(id -u) != 0 ]]; then
  echo "manual release Host operations are trusted root/operator actions" >&2
  exit 77
fi

readonly source_sha="$2"
readonly manifest_sha256="$3"
readonly bundle_sha256="$4"
readonly control_image_reference="$5"
readonly credential_refresher_image_reference="$6"
readonly gateway_image_reference="$7"
for image_reference in \
  "${control_image_reference}" \
  "${credential_refresher_image_reference}" \
  "${gateway_image_reference}"; do
  [[ ${image_reference} == */*:* && ${image_reference} != *@* && ${image_reference} != *[[:space:]]* ]] || {
    echo "manual release image references must be explicit repository:tag values" >&2
    exit 64
  }
done
readonly source_dir="/srv/cats-build/source"
readonly target_parent="/srv/cats-build/target"
readonly build_receipt_dir="/var/lib/cats-build/build-receipts"
readonly preparation_dir="/var/lib/cats-build/manual-release-preparations"
readonly source_receipt="/var/lib/cats-build/source-receipts/${source_sha}-${manifest_sha256}.json"
readonly active_delivery="${source_dir}/.git/cats-active-delivery-v1.json"
readonly base_lock="/opt/cats-build/toolchain-lock-v1.json"
readonly identity_file="/etc/cats-build/identity.json"
readonly readiness_file="/var/lib/cats-build/readiness-v1.json"
readonly receipt_library="${source_dir}/deploy/aws/terraform/qualification/build-host/bootstrap/immutable-receipt.sh"
readonly lock_file="${source_dir}/deploy/aws/terraform/qualification/build-host/tools/manual-release-toolchain-lock-v1.json"
readonly builder="${source_dir}/deploy/aws/tools/build-manual-release.sh"
readonly this_script="$(readlink -f -- "${BASH_SOURCE[0]}")"
readonly source_lock="/run/lock/cats-source-delivery.lock"

install -d -m 0755 -o root -g root /run/lock
exec 9>"${source_lock}"
flock -x 9

git_safe() {
  env -i \
    PATH=/usr/local/bin:/usr/bin:/bin \
    HOME=/run/cats-manual-release-git \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

require_root_immutable() {
  local path="$1"
  [[ -f ${path} && ! -L ${path} && $(stat -c '%u:%a' "${path}") == "0:444" ]] || {
    echo "expected root-owned immutable file: ${path}" >&2
    exit 65
  }
}

readonly resolved_source="$(git_safe -C "${source_dir}" rev-parse --show-toplevel)"
[[ ${resolved_source} == "${source_dir}" && $(readlink -f -- "${resolved_source}") == "${source_dir}" ]] || {
  echo "manual release helper must run from the frozen exact source" >&2
  exit 65
}
readonly resolved_sha="$(git_safe -C "${source_dir}" rev-parse HEAD)"
readonly tree_sha="$(git_safe -C "${source_dir}" rev-parse 'HEAD^{tree}')"
[[ ${resolved_sha} == "${source_sha}" ]] || {
  echo "published source is not the requested exact commit" >&2
  exit 65
}
[[ -z $(git_safe -C "${source_dir}" status --porcelain=v1 --untracked-files=all) ]] || {
  echo "published source is dirty" >&2
  exit 65
}
for immutable_file in \
  "${source_receipt}" \
  "${active_delivery}" \
  "${identity_file}" \
  "${readiness_file}"; do
  require_root_immutable "${immutable_file}"
done
for source_input in "${receipt_library}" "${lock_file}" "${builder}" "${this_script}"; do
  [[ -f ${source_input} && ! -L ${source_input} && $(stat -c '%u' "${source_input}") == 0 ]] || {
    echo "manual release input is not a root-owned regular file: ${source_input}" >&2
    exit 65
  }
done
jq -e \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  '.source_sha == $source_sha and .tree_sha == $tree_sha and
   .manifest_sha256 == $manifest_sha256 and .bundle_sha256 == $bundle_sha256 and
   .source_owner == "root" and .source_writable_by_build == false' \
  "${source_receipt}" >/dev/null
jq -e \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  'keys == ["bundle_sha256", "manifest_sha256", "schema_version", "source_sha", "tree_sha"] and
   .schema_version == 1 and .source_sha == $source_sha and .tree_sha == $tree_sha and
   .manifest_sha256 == $manifest_sha256 and .bundle_sha256 == $bundle_sha256' \
  "${active_delivery}" >/dev/null

# shellcheck source=/dev/null
source "${receipt_library}"

readonly manual_lock_sha256="$(hash_file "${lock_file}")"
readonly helper_sha256="$(hash_file "${this_script}")"
readonly base_lock_sha256="$(jq -er '.base_toolchain_lock_sha256' "${lock_file}")"
readonly tool_root="/opt/cats-manual-release/${manual_lock_sha256}"
readonly preparation_receipt="${preparation_dir}/${manual_lock_sha256}-${helper_sha256}.json"
readonly rust_toolchain="$(jq -er '.rust.toolchain' "${lock_file}")"
readonly rust_target="$(jq -er '.rust.target' "${lock_file}")"
readonly buildx_sha256="$(jq -er '.downloads.buildx.sha256' "${lock_file}")"
readonly buildx_version="$(jq -er '.downloads.buildx.install_version' "${lock_file}")"
readonly snapshot_id="$(jq -er '.apt_snapshot_id' "${lock_file}")"

verify_base_host() {
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
    echo "manual release requires native Linux x86_64" >&2
    return 1
  }
  [[ $(hash_file "${base_lock}") == "${base_lock_sha256}" ]] || {
    echo "installed qualification toolchain lock differs from the manual release lock" >&2
    return 1
  }
  [[ $(jq -er '.apt_snapshot.snapshot_id' "${base_lock}") == "${snapshot_id}" ]] || {
    echo "installed APT snapshot differs from the manual release lock" >&2
    return 1
  }
  [[ $(grep -Fxc "Snapshot: ${snapshot_id}" /etc/apt/sources.list.d/ubuntu.sources) -eq 2 ]] || {
    echo "qualification APT sources are not pinned to the reviewed snapshot" >&2
    return 1
  }
  python3 /usr/local/bin/cats-verify-build-host-readiness >/dev/null
  systemctl is-active --quiet docker.service
  systemctl is-active --quiet buildkit.service
  [[ $(docker version --format '{{.Server.Os}}/{{.Server.Arch}}') == linux/amd64 ]] || {
    echo "Docker daemon is not native linux/amd64" >&2
    return 1
  }
  [[ $(docker version --format '{{.Server.Version}}') == "$(jq -er '.docker.server_version' "${lock_file}")" ]] || {
    echo "Docker daemon version differs from the manual release lock" >&2
    return 1
  }
  for required in \
    apt-get awk curl docker dpkg-query git grep install jq python3 sha256sum stat tar timeout zstd \
    mkfs.ext4 mountpoint chroot truncate find flock systemd-run; do
    command -v "${required}" >/dev/null 2>&1 || {
      echo "manual release base Host needs ${required}" >&2
      return 1
    }
  done
  local kernel_release
  kernel_release="$(uname -r)"
  [[ -f /boot/vmlinuz-${kernel_release} && ! -L /boot/vmlinuz-${kernel_release} ]] || {
    echo "native build Host kernel is unavailable: /boot/vmlinuz-${kernel_release}" >&2
    return 1
  }
  [[ -f /lib/modules/${kernel_release}/modules.dep && ! -L /lib/modules/${kernel_release}/modules.dep ]] || {
    echo "native build Host module index is unavailable for ${kernel_release}" >&2
    return 1
  }
  local available_bytes
  available_bytes="$(df -PB1 "${target_parent}" | awk 'NR == 2 {print $4}')"
  (( available_bytes >= $(jq -er '.limits.minimum_build_filesystem_free_bytes' "${lock_file}") )) || {
    echo "qualification build filesystem has less than the locked free-space floor" >&2
    return 1
  }
}

package_versions_json() {
  local name expected actual
  local entries=()
  while IFS=$'\t' read -r name expected; do
    actual="$(dpkg-query -W -f='${Version}' "${name}" 2>/dev/null || true)"
    [[ ${actual} == "${expected}" ]] || {
      echo "${name}: expected ${expected}, observed ${actual:-absent}" >&2
      return 1
    }
    entries+=("$(jq -cn --arg name "${name}" --arg version "${actual}" '{name:$name,version:$version}')")
  done < <(jq -r '.apt_packages | to_entries | sort_by(.key)[] | [.key,.value] | @tsv' "${lock_file}")
  printf '%s\n' "${entries[@]}" | jq -sS 'sort_by(.name)'
}

verify_manual_tools() {
  verify_base_host
  package_versions_json >/dev/null
  for required in busybox cpio debootstrap gzip modprobe rustup sudo; do
    PATH="${tool_root}/cargo/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin" \
      command -v "${required}" >/dev/null 2>&1 || {
      echo "manual release Guest build needs ${required}" >&2
      return 1
    }
  done
  [[ -d ${tool_root} && ! -L ${tool_root} && $(stat -c '%u:%a' "${tool_root}") == "0:555" ]] || {
    echo "versioned manual release tool root is not frozen" >&2
    return 1
  }
  # Symlink modes are immutably 0777 on Linux (rustup >= 1.28 installs its
  # proxies as symlinks); containment comes from the 0555 parent directories,
  # so only real files and directories count as writable data.
  if find -P "${tool_root}" -xdev ! -type l -perm /0222 -print -quit | grep -q .; then
    echo "versioned manual release tool root contains writable data" >&2
    return 1
  fi
  [[ $(hash_file "${tool_root}/bin/docker-buildx") == "${buildx_sha256}" ]] || {
    echo "manual release buildx digest differs from the lock" >&2
    return 1
  }
  [[ $("${tool_root}/bin/docker-buildx" version | awk '{print $2}') == "${buildx_version}" ]] || {
    echo "manual release buildx version differs from the lock" >&2
    return 1
  }
  [[ $(env RUSTUP_HOME="${tool_root}/rustup" "${tool_root}/cargo/bin/rustc" --version) == "rustc ${rust_toolchain}"* ]] || {
    echo "manual release Rust toolchain differs from the lock" >&2
    return 1
  }
  env RUSTUP_HOME="${tool_root}/rustup" "${tool_root}/cargo/bin/rustup" \
    target list --installed --toolchain "${rust_toolchain}" | grep -Fxq "${rust_target}"
  local module
  for module in virtio_pci virtio_blk virtio_net vmw_vsock_virtio_transport ext4; do
    modprobe --show-depends "${module}" >/dev/null
  done
}

verify_preparation_receipt() {
  require_root_immutable "${preparation_receipt}"
  jq -e \
    --arg lock_sha256 "${manual_lock_sha256}" \
    --arg helper_sha256 "${helper_sha256}" \
    --arg base_lock_sha256 "${base_lock_sha256}" \
    --arg tool_root "${tool_root}" \
    --arg kernel_release "$(uname -r)" \
    --arg kernel_sha256 "$(hash_file "/boot/vmlinuz-$(uname -r)")" \
    --arg modules_dep_sha256 "$(hash_file "/lib/modules/$(uname -r)/modules.dep")" \
    '.schema_version == 1 and .status == "ready" and
     .manual_release_lock_sha256 == $lock_sha256 and
     .helper_sha256 == $helper_sha256 and
     .base_toolchain_lock_sha256 == $base_lock_sha256 and
     .tool_root == $tool_root and .kernel_release == $kernel_release and
     .kernel_sha256 == $kernel_sha256 and
     .modules_dep_sha256 == $modules_dep_sha256 and
     .registry_credentials_used == false and .candidate_build_uid_changed == false' \
    "${preparation_receipt}" >/dev/null
}

verify_and_report() {
  verify_manual_tools
  verify_preparation_receipt
  jq -nS \
    --arg source_sha "${source_sha}" \
    --arg tree_sha "${tree_sha}" \
    --arg manifest_sha256 "${manifest_sha256}" \
    --arg bundle_sha256 "${bundle_sha256}" \
    --arg preparation_receipt "${preparation_receipt}" \
    --arg preparation_receipt_sha256 "$(hash_file "${preparation_receipt}")" \
    --arg manual_release_lock_sha256 "${manual_lock_sha256}" \
    --arg kernel_release "$(uname -r)" \
    '{schema_version:1,status:"ready",source_sha:$source_sha,tree_sha:$tree_sha,
      manifest_sha256:$manifest_sha256,bundle_sha256:$bundle_sha256,
      preparation_receipt:$preparation_receipt,
      preparation_receipt_sha256:$preparation_receipt_sha256,
      manual_release_lock_sha256:$manual_release_lock_sha256,
      kernel_release:$kernel_release,native_platform:"linux/amd64",
      registry_credentials_used:false,candidate_build_uid_changed:false}'
}

prepare_host() {
  if [[ -e ${preparation_receipt} || -L ${preparation_receipt} ]]; then
    verify_and_report
    return
  fi
  verify_base_host
  # The EXIT trap runs outside this function's scope under errexit, so these
  # cleanup paths must not be function locals.
  work_dir="$(mktemp -d /var/tmp/cats-manual-release-prepare.XXXXXX)"
  stage_root="/opt/cats-manual-release/.${manual_lock_sha256}.incomplete.$$"
  prepared_receipt=""
  cleanup_prepare() {
    rm -rf -- "${work_dir:-/nonexistent}" "${stage_root:-/nonexistent}"
    [[ -z ${prepared_receipt:-} || ! -e ${prepared_receipt:-} ]] || rm -f -- "${prepared_receipt}"
  }
  trap cleanup_prepare EXIT
  chmod 0700 "${work_dir}"

  local name destination url expected_sha actual_sha
  for name in buildx rustup_init; do
    # rustup-init dispatches on argv[0]; an underscore basename is rejected as
    # an unknown proxy name, so downloads keep the canonical hyphenated names.
    destination="${work_dir}/${name//_/-}"
    url="$(jq -er --arg name "${name}" '.downloads[$name].url' "${lock_file}")"
    expected_sha="$(jq -er --arg name "${name}" '.downloads[$name].sha256' "${lock_file}")"
    curl --fail --location --proto '=https' --tlsv1.2 --output "${destination}" "${url}"
    actual_sha="$(hash_file "${destination}")"
    [[ ${actual_sha} == "${expected_sha}" ]] || {
      echo "${name}: SHA-256 mismatch" >&2
      return 1
    }
    chmod 0500 "${destination}"
  done

  export DEBIAN_FRONTEND=noninteractive
  timeout --signal=TERM 600 apt-get update
  local apt_specs=()
  while IFS=$'\t' read -r name expected_sha; do
    apt_specs+=("${name}=${expected_sha}")
  done < <(jq -r '.apt_packages | to_entries | sort_by(.key)[] | [.key,.value] | @tsv' "${lock_file}")
  timeout --signal=TERM 900 apt-get install -y --no-install-recommends --allow-downgrades "${apt_specs[@]}"
  apt-mark hold "${apt_specs[@]%%=*}" >/dev/null

  if [[ ! -e ${tool_root} ]]; then
    [[ ! -e ${stage_root} && ! -L ${stage_root} ]] || {
      echo "manual release tool staging path already exists" >&2
      return 1
    }
    install -d -m 0700 "${stage_root}/cargo" "${stage_root}/rustup" "${stage_root}/bin"
    env \
      HOME="${work_dir}" \
      CARGO_HOME="${stage_root}/cargo" \
      RUSTUP_HOME="${stage_root}/rustup" \
      RUSTUP_INIT_SKIP_PATH_CHECK=yes \
      "${work_dir}/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none
    env CARGO_HOME="${stage_root}/cargo" RUSTUP_HOME="${stage_root}/rustup" \
      "${stage_root}/cargo/bin/rustup" toolchain install "${rust_toolchain}" \
      --profile minimal --target "${rust_target}"
    env CARGO_HOME="${stage_root}/cargo" RUSTUP_HOME="${stage_root}/rustup" \
      "${stage_root}/cargo/bin/rustup" default "${rust_toolchain}"
    install -o root -g root -m 0555 "${work_dir}/buildx" "${stage_root}/bin/docker-buildx"
    chown -R root:root "${stage_root}"
    chmod -R a-w "${stage_root}"
    chmod 0555 "${stage_root}"
    install -d -m 0755 -o root -g root /opt/cats-manual-release
    mv -- "${stage_root}" "${tool_root}"
  fi

  verify_manual_tools
  install -d -m 0755 -o root -g root "${preparation_dir}"
  prepared_receipt="$(mktemp "${preparation_dir}/.${manual_lock_sha256}.XXXXXX")"
  jq -nS \
    --arg prepared_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg manual_release_lock_sha256 "${manual_lock_sha256}" \
    --arg helper_sha256 "${helper_sha256}" \
    --arg base_toolchain_lock_sha256 "${base_lock_sha256}" \
    --arg tool_root "${tool_root}" \
    --arg buildx_version "${buildx_version}" \
    --arg buildx_sha256 "${buildx_sha256}" \
    --arg rust_toolchain "${rust_toolchain}" \
    --arg rust_target "${rust_target}" \
    --arg kernel_release "$(uname -r)" \
    --arg kernel_sha256 "$(hash_file "/boot/vmlinuz-$(uname -r)")" \
    --arg modules_dep_sha256 "$(hash_file "/lib/modules/$(uname -r)/modules.dep")" \
    --arg readiness_sha256 "$(hash_file "${readiness_file}")" \
    --argjson apt_packages "$(package_versions_json)" \
    '{schema_version:1,status:"ready",prepared_at:$prepared_at,
      manual_release_lock_sha256:$manual_release_lock_sha256,
      helper_sha256:$helper_sha256,base_toolchain_lock_sha256:$base_toolchain_lock_sha256,
      tool_root:$tool_root,buildx:{version:$buildx_version,sha256:$buildx_sha256},
      rust:{toolchain:$rust_toolchain,target:$rust_target},apt_packages:$apt_packages,
      kernel_release:$kernel_release,kernel_sha256:$kernel_sha256,
      modules_dep_sha256:$modules_dep_sha256,readiness_sha256:$readiness_sha256,
      native_platform:"linux/amd64",registry_credentials_used:false,
      candidate_build_uid_changed:false}' >"${prepared_receipt}"
  write_immutable_receipt "${prepared_receipt}" "${preparation_receipt}"
  prepared_receipt=""
  chown root:root "${preparation_receipt}"
  verify_and_report
  cleanup_prepare
  trap - EXIT
}

run_build() {
  verify_manual_tools
  verify_preparation_receipt

  readonly target_base="${target_parent}/${source_sha}-${manifest_sha256}-${bundle_sha256}"
  install -d -m 0755 -o root -g root "${target_base}"
  readonly job_dir="$(mktemp -d "${target_base}/job.XXXXXX")"
  readonly job_id="$(basename -- "${job_dir}")"
  readonly output_dir="${job_dir}/output"
  readonly release_dir="${output_dir}/release"
  readonly build_log="${output_dir}/manual-release-build.log"
  readonly transport_archive="${output_dir}/cats-manual-release-${source_sha}.tar.zst"
  install -d -m 0700 -o root -g root \
    "${job_dir}/home" "${job_dir}/cargo-home" "${job_dir}/tmp" \
    "${job_dir}/bin" "${job_dir}/docker-config/cli-plugins" "${output_dir}"
  ln -s "${tool_root}/bin/docker-buildx" "${job_dir}/docker-config/cli-plugins/docker-buildx"
  install -m 0500 /dev/stdin "${job_dir}/bin/rustup" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ \$# -eq 3 && \$1 == target && \$2 == add && \$3 == ${rust_target} ]]; then
  exec env RUSTUP_HOME=${tool_root}/rustup ${tool_root}/cargo/bin/rustup \\
    target list --installed --toolchain ${rust_toolchain}
fi
echo "manual release rustup wrapper accepts only the preinstalled ${rust_target} target" >&2
exit 64
EOF

  local status=0
  readonly systemd_unit="cats-manual-release-${job_id//./-}"
  set +e
  systemd-run --quiet --wait --collect --pipe \
    --unit "${systemd_unit}" \
    --service-type=exec \
    --property=KillMode=control-group \
    --property=SendSIGKILL=yes \
    --property=PrivateIPC=true \
    --property=LimitNOFILE=65536 \
    --property=TasksMax=infinity \
    /usr/bin/env -i \
      HOME="${job_dir}/home" \
      USER=root \
      LOGNAME=root \
      PATH="${job_dir}/bin:${tool_root}/cargo/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin" \
      CARGO_HOME="${job_dir}/cargo-home" \
      RUSTUP_HOME="${tool_root}/rustup" \
      RUSTUP_TOOLCHAIN="${rust_toolchain}" \
      DOCKER_CONFIG="${job_dir}/docker-config" \
      TMPDIR="${job_dir}/tmp" \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_TERMINAL_PROMPT=0 \
      bash -c 'cd /srv/cats-build/source && exec deploy/aws/tools/build-manual-release.sh --source-sha "$1" --output "$2" --image "$3" --credential-refresher-image "$4" --gateway-image "$5" --export-images' \
      cats-manual-release "${source_sha}" "${release_dir}" \
      "${control_image_reference}" "${credential_refresher_image_reference}" \
      "${gateway_image_reference}" \
    2>&1 | tee "${build_log}"
  local -a pipeline_status=("${PIPESTATUS[@]}")
  status=${pipeline_status[0]}
  if (( status == 0 && pipeline_status[1] != 0 )); then
    status=${pipeline_status[1]}
  fi
  set -e

  if (( status == 0 )); then
    set +e
    (
      cd "${release_dir}"
      sha256sum --check SHA256SUMS
      jq -e \
        --arg source_sha "${source_sha}" \
        --arg control_image_reference "${control_image_reference}" \
        --arg credential_refresher_image_reference "${credential_refresher_image_reference}" \
        --arg gateway_image_reference "${gateway_image_reference}" \
        '.source.commit == $source_sha and
         .artifacts.control_plane.image_reference == $control_image_reference and
         .artifacts.credential_refresher.image_reference == $credential_refresher_image_reference and
         .artifacts.gateway.image_reference == $gateway_image_reference and
         .artifacts.control_plane.registry_verified == false and
         .artifacts.credential_refresher.registry_verified == false and
         .artifacts.gateway.registry_verified == false' \
        release-manifest.v1.json >/dev/null
      find . -type f ! -name release-files.sha256 -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 sha256sum >release-files.sha256
      tar --owner=0 --group=0 --numeric-owner --sort=name \
        --mtime='UTC 1970-01-01' -cf - . \
        | zstd -19 -T0 -o "${transport_archive}"
      (( $(stat -c '%s' "${transport_archive}") <= $(jq -er '.limits.maximum_transport_archive_bytes' "${lock_file}") ))
    )
    status=$?
    set -e
  fi

  chown -R root:root "${output_dir}"
  find -P "${output_dir}" -xdev -type d -exec chmod 0555 {} +
  find -P "${output_dir}" -xdev -type f -exec chmod 0444 {} +
  chown root:root "${job_dir}"
  chmod 0555 "${job_dir}"

  install -d -m 0755 -o root -g root "${build_receipt_dir}"
  local prepared_build_receipt build_receipt_path command_json archive_sha256
  prepared_build_receipt="$(mktemp "${build_receipt_dir}/.${job_id}.XXXXXX")"
  build_receipt_path="${build_receipt_dir}/${job_id}.json"
  command_json="$(printf '%s\0' \
    deploy/aws/tools/build-manual-release.sh \
    --source-sha "${source_sha}" --output "${release_dir}" \
    --image "${control_image_reference}" \
    --credential-refresher-image "${credential_refresher_image_reference}" \
    --gateway-image "${gateway_image_reference}" --export-images \
    | jq -Rs 'split("\u0000")[:-1]')"
  archive_sha256=""
  [[ ! -f ${transport_archive} ]] || archive_sha256="$(hash_file "${transport_archive}")"
  jq -nS \
    --arg source_sha "${source_sha}" \
    --arg tree_sha "${tree_sha}" \
    --arg manifest_sha256 "${manifest_sha256}" \
    --arg bundle_sha256 "${bundle_sha256}" \
    --arg control_image_reference "${control_image_reference}" \
    --arg credential_refresher_image_reference "${credential_refresher_image_reference}" \
    --arg gateway_image_reference "${gateway_image_reference}" \
    --arg job_id "${job_id}" \
    --arg job_dir "${job_dir}" \
    --arg output_dir "${output_dir}" \
    --arg source_receipt "${source_receipt}" \
    --arg bootstrap_payload_sha256 "$(jq -er '.bootstrap_payload_sha256' "${identity_file}")" \
    --arg preparation_receipt "${preparation_receipt}" \
    --arg preparation_receipt_sha256 "$(hash_file "${preparation_receipt}")" \
    --arg manual_release_lock_sha256 "${manual_lock_sha256}" \
    --arg helper_sha256 "${helper_sha256}" \
    --arg transport_archive "${transport_archive}" \
    --arg transport_archive_sha256 "${archive_sha256}" \
    --argjson command "${command_json}" \
    --argjson exit_status "${status}" \
    '{schema_version:1,source_sha:$source_sha,tree_sha:$tree_sha,
      manifest_sha256:$manifest_sha256,bundle_sha256:$bundle_sha256,
      control_image_reference:$control_image_reference,
      credential_refresher_image_reference:$credential_refresher_image_reference,
      gateway_image_reference:$gateway_image_reference,
      job_id:$job_id,job_dir:$job_dir,output_dir:$output_dir,
      source_receipt:$source_receipt,command:$command,with_postgres:false,
      exit_status:$exit_status,bootstrap_payload_sha256:$bootstrap_payload_sha256,
      build_kind:"manual-release-export-images",
      preparation_receipt:$preparation_receipt,
      preparation_receipt_sha256:$preparation_receipt_sha256,
      manual_release_lock_sha256:$manual_release_lock_sha256,
      helper_sha256:$helper_sha256,transport_archive:$transport_archive,
      transport_archive_sha256:$transport_archive_sha256,
      aws_environment_forwarded:false,registry_credentials_used:false,
      reusable_home:false,job_cgroup_drained:true,output_frozen:true}' \
    >"${prepared_build_receipt}"
  write_immutable_receipt "${prepared_build_receipt}" "${build_receipt_path}"
  chown root:root "${build_receipt_path}"
  printf 'build receipt: %s\n' "${build_receipt_path}"
  if (( status == 0 )); then
    jq -cnS \
      --arg source_sha "${source_sha}" \
      --arg output_dir "${output_dir}" \
      --arg transport_archive "${transport_archive}" \
      --arg transport_archive_sha256 "${archive_sha256}" \
      --arg build_receipt "${build_receipt_path}" \
      --arg build_receipt_sha256 "$(hash_file "${build_receipt_path}")" \
      '{schema_version:1,status:"built",source_sha:$source_sha,output_dir:$output_dir,
        transport_archive:$transport_archive,
        transport_archive_sha256:$transport_archive_sha256,
        build_receipt:$build_receipt,build_receipt_sha256:$build_receipt_sha256}'
  fi
  return "${status}"
}

case "${operation}" in
  prepare) prepare_host ;;
  verify) verify_and_report ;;
  build) run_build ;;
esac
