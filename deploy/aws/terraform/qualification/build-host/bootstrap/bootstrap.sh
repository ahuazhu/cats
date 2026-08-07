#!/usr/bin/env bash
set -euo pipefail

readonly lock_file="/opt/cats-build/toolchain-lock-v1.json"
readonly identity_file="/etc/cats-build/identity.json"
readonly work_dir="$(mktemp -d /var/tmp/cats-build-bootstrap.XXXXXX)"
toolchain_needs_refreeze=false
readonly -a toolchain_paths=(
  /opt/cats-build/cargo
  /opt/cats-build/rustup
)

thaw_toolchain() {
  toolchain_needs_refreeze=true
  install -d -m 0755 "${toolchain_paths[@]}"
  chown -R cats-build:cats-build "${toolchain_paths[@]}"
  chmod -R u+rwX,go+rX,go-w "${toolchain_paths[@]}"
}

freeze_toolchain() {
  chown -R root:root "${toolchain_paths[@]}"
  chmod -R a-w "${toolchain_paths[@]}"
  toolchain_needs_refreeze=false
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "${toolchain_needs_refreeze}" == "true" ]]; then
    chown -R root:root "${toolchain_paths[@]}" || status=$?
    chmod -R a-w "${toolchain_paths[@]}" || status=$?
  fi
  rm -rf -- "${work_dir}" || status=$?
  exit "${status}"
}
trap cleanup EXIT
chmod 0755 "${work_dir}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "qualification build host must be x86_64" >&2
  exit 1
fi
sha256sum --check --status <(
  printf '%s  %s\n' "$(jq -er '.toolchain_lock_sha256' "${identity_file}")" "${lock_file}"
)

test -s /etc/ssl/certs/ca-certificates.crt
for source_file in \
  /etc/apt/sources.list \
  /etc/apt/sources.list.d/*.list \
  /etc/apt/sources.list.d/*.sources; do
  [[ -f "${source_file}" ]] || continue
  sed -i -E \
    -e 's#(URIs:[[:space:]]*)http://#\1https://#g' \
    -e 's#(^deb(-src)?[[:space:]]+)http://#\1https://#g' \
    "${source_file}"
done
if grep -R -h -E --include='*.list' --include='*.sources' 'http://' /etc/apt \
  | awk '{ sub(/[[:space:]]*#.*/, ""); if ($0 ~ /(^|[[:space:]])http:\/\//) found = 1 } END { exit found ? 0 : 1 }'; then
  echo "an HTTP APT source remains after HTTPS migration" >&2
  exit 1
fi

readonly snapshot_id="$(jq -er '.apt_snapshot.snapshot_id' "${lock_file}")"
readonly archive_url="$(jq -er '.apt_snapshot.archive_url' "${lock_file}")"
readonly security_url="$(jq -er '.apt_snapshot.security_url' "${lock_file}")"
for source_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [[ -f "${source_file}" ]] || continue
  if [[ "${source_file}" != "/etc/apt/sources.list.d/ubuntu.sources" ]]; then
    mv -- "${source_file}" "${source_file}.disabled-by-cats"
  fi
done
install -m 0644 /dev/stdin /etc/apt/sources.list.d/ubuntu.sources <<EOF
Types: deb
URIs: ${archive_url}
Suites: noble noble-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Snapshot: ${snapshot_id}

Types: deb
URIs: ${security_url}
Suites: noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Snapshot: ${snapshot_id}
EOF
install -m 0644 /dev/stdin /etc/apt/apt.conf.d/99-cats-qualification <<'EOF'
APT::Periodic::Enable "0";
APT::Periodic::Unattended-Upgrade "0";
Acquire::Retries "5";
EOF

export DEBIAN_FRONTEND=noninteractive
apt-get update
mapfile -t apt_packages < <(
  jq -r '.apt_snapshot.packages | to_entries | sort_by(.key)[] | "\(.key)=\(.value)"' "${lock_file}"
)
apt-get install -y --no-install-recommends "${apt_packages[@]}"
mapfile -t apt_package_names < <(jq -r '.apt_snapshot.packages | keys[]' "${lock_file}")
apt-mark hold "${apt_package_names[@]}"
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service 2>/dev/null || true

download_verified() {
  local name="$1"
  local destination="$2"
  local url expected_sha actual_sha
  url="$(jq -er --arg name "${name}" '.downloads[$name].url' "${lock_file}")"
  expected_sha="$(jq -er --arg name "${name}" '.downloads[$name].sha256' "${lock_file}")"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "${destination}" "${url}"
  actual_sha="$(sha256sum "${destination}" | awk '{print $1}')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "${name}: SHA-256 mismatch" >&2
    exit 1
  fi
}

download_verified docker "${work_dir}/docker.tgz"
tar -xzf "${work_dir}/docker.tgz" --strip-components=1 -C /usr/local/bin
install -m 0644 /dev/stdin /etc/systemd/system/docker.service <<'EOF'
[Unit]
Description=Cats qualification Docker daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd --host=unix:///run/docker.sock --group=root --storage-driver=overlay2
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

download_verified buildkit "${work_dir}/buildkit.tgz"
tar -xzf "${work_dir}/buildkit.tgz" --strip-components=1 -C /usr/local/bin
install -m 0644 /dev/stdin /etc/systemd/system/buildkit.service <<'EOF'
[Unit]
Description=Cats qualification BuildKit daemon
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/buildkitd --addr unix:///run/buildkit/buildkitd.sock --group root --oci-worker-net=bridge
Restart=always
RestartSec=2
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

download_verified aws_cli "${work_dir}/awscliv2.zip"
unzip -q "${work_dir}/awscliv2.zip" -d "${work_dir}/aws-cli"
"${work_dir}/aws-cli/aws/install" --install-dir /usr/local/aws-cli --bin-dir /usr/local/bin --update

if getent passwd 2000 >/dev/null && [[ "$(getent passwd 2000 | cut -d: -f1)" != "cats-build" ]]; then
  echo "UID 2000 is already assigned to another account" >&2
  exit 1
fi
id cats-build >/dev/null 2>&1 || useradd --create-home --uid 2000 --shell /bin/bash cats-build
install -d -m 0755 -o root -g root \
  /srv/cats-build /srv/cats-build/target \
  /var/lib/cats-build /var/lib/cats-build/source-receipts

download_verified rustup_init "${work_dir}/rustup-init"
chmod 0755 "${work_dir}/rustup-init"
readonly rust_toolchain="$(jq -er '.rust.toolchain' "${lock_file}")"
thaw_toolchain
runuser -u cats-build -- env \
  HOME=/home/cats-build \
  CARGO_HOME=/opt/cats-build/cargo \
  RUSTUP_HOME=/opt/cats-build/rustup \
  "${work_dir}/rustup-init" -y --profile minimal --default-toolchain none
runuser -u cats-build -- env \
  HOME=/home/cats-build \
  CARGO_HOME=/opt/cats-build/cargo \
  RUSTUP_HOME=/opt/cats-build/rustup \
  /opt/cats-build/cargo/bin/rustup toolchain install "${rust_toolchain}" \
    --profile minimal --component clippy,rustfmt
runuser -u cats-build -- env \
  HOME=/home/cats-build \
  CARGO_HOME=/opt/cats-build/cargo \
  RUSTUP_HOME=/opt/cats-build/rustup \
  /opt/cats-build/cargo/bin/rustup default "${rust_toolchain}"
for cargo_tool in cargo_deny cargo_machete; do
  crate_name="${cargo_tool//_/-}"
  crate_version="$(jq -er --arg name "${cargo_tool}" '.rust[$name]' "${lock_file}")"
  runuser -u cats-build -- env \
    HOME=/home/cats-build \
    CARGO_HOME=/opt/cats-build/cargo \
    RUSTUP_HOME=/opt/cats-build/rustup \
    /opt/cats-build/cargo/bin/cargo install --locked \
      --version "${crate_version}" "${crate_name}"
done
freeze_toolchain
install -m 0644 /dev/stdin /etc/profile.d/cats-build.sh <<'EOF'
export RUSTUP_HOME=/opt/cats-build/rustup
export PATH=/opt/cats-build/cargo/bin:/usr/local/bin:$PATH
EOF

install -m 0600 /dev/stdin "${work_dir}/imds-probe.c" <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "offline") == 0) return 0;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return 2;
  struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(80)};
  if (inet_pton(AF_INET, "169.254.169.254", &address.sin_addr) != 1) return 2;
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 2;
  const char request[] = "PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\nConnection: close\r\n\r\n";
  if (write(fd, request, sizeof(request) - 1) < 0) return 2;
  char response[16];
  int received = read(fd, response, sizeof(response));
  close(fd);
  return received > 0 ? 0 : 2;
}
EOF
cc -static -O2 -Wall -Wextra -Werror "${work_dir}/imds-probe.c" -o "${work_dir}/imds-probe"
install -m 0555 -o root -g root "${work_dir}/imds-probe" /usr/local/libexec/cats-build/imds-probe

sed -i -E 's/^(pool|server)[[:space:]]+/# disabled by Cats qualification: &/' /etc/chrony/chrony.conf
for source_file in /etc/chrony/sources.d/*; do
  [[ -f "${source_file}" ]] || continue
  mv -- "${source_file}" "${source_file}.disabled-by-cats"
done
install -m 0644 /dev/stdin /etc/chrony/conf.d/cats-aws-time.conf <<'EOF'
server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4
EOF

systemctl daemon-reload
systemctl enable --now cats-build-imds-guard.service
systemctl enable --now chrony.service docker.service buildkit.service
chronyc waitsync 60 0.1 0.0 1

if systemctl list-unit-files snap.amazon-ssm-agent.amazon-ssm-agent.service >/dev/null 2>&1; then
  snap refresh --hold=forever amazon-ssm-agent
  systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service
elif systemctl list-unit-files amazon-ssm-agent.service >/dev/null 2>&1; then
  systemctl enable --now amazon-ssm-agent.service
else
  echo "pinned Canonical AMI does not contain Amazon SSM Agent" >&2
  exit 1
fi

readonly imds_token="$(curl --fail --silent --show-error --request PUT \
  --header 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
  http://169.254.169.254/latest/api/token)"
readonly instance_document="$(curl --fail --silent --show-error \
  --header "X-aws-ec2-metadata-token: ${imds_token}" \
  http://169.254.169.254/latest/dynamic/instance-identity/document)"
jq -e \
  --arg account_id "$(jq -er '.account_id' "${identity_file}")" \
  --arg ami_id "$(jq -er '.ami_id' "${identity_file}")" \
  --arg instance_type "$(jq -er '.instance_type' "${identity_file}")" \
  --arg region "$(jq -er '.region' "${identity_file}")" \
  '.accountId == $account_id and .imageId == $ami_id and .instanceType == $instance_type and .region == $region' \
  <<<"${instance_document}" >/dev/null

readonly root_source="$(findmnt -n -o SOURCE /)"
readonly root_size_bytes="$(lsblk -bno SIZE "$(readlink -f "${root_source}")" | head -1)"
if (( root_size_bytes < 490 * 1024 * 1024 * 1024 )); then
  echo "root filesystem is smaller than the reviewed 500 GiB volume" >&2
  exit 1
fi

readonly package_manifest="$(
  dpkg-query -W -f='${Package}\t${Version}\n' "${apt_package_names[@]}" \
    | jq -Rn '[inputs | split("\t") | {name: .[0], version: .[1]}]'
)"
readonly ssm_version="$(snap list amazon-ssm-agent 2>/dev/null | awk 'NR == 2 {print $2}')"
readonly rust_version="$(
  runuser -u cats-build -- env \
    HOME=/home/cats-build \
    CARGO_HOME=/opt/cats-build/cargo \
    RUSTUP_HOME=/opt/cats-build/rustup \
    /opt/cats-build/cargo/bin/rustc --version
)"
jq -n -S \
  --argjson identity "$(<"${identity_file}")" \
  --argjson instance_document "${instance_document}" \
  --argjson packages "${package_manifest}" \
  --arg aws_cli_version "$(aws --version 2>&1)" \
  --arg buildkit_version "$(buildctl --version)" \
  --arg cargo_deny_version "$(/opt/cats-build/cargo/bin/cargo-deny --version)" \
  --arg cargo_machete_version "$(/opt/cats-build/cargo/bin/cargo-machete --version)" \
  --arg docker_version "$(docker --version)" \
  --arg rust_version "${rust_version}" \
  --arg ssm_agent_version "${ssm_version}" \
  --argjson root_size_bytes "${root_size_bytes}" \
  '{
    schema_version: 1,
    status: "ready",
    qualification: {
      account_id: $identity.account_id,
      region: $identity.region,
      namespace: $identity.namespace,
      cell_id: $identity.cell_id
    },
    host: {
      instance_id: $instance_document.instanceId,
      availability_zone: $instance_document.availabilityZone,
      ami_id: $instance_document.imageId,
      instance_type: $instance_document.instanceType,
      architecture: "x86_64",
      root_size_bytes: $root_size_bytes,
      imdsv2_required: true,
      public_ip_allowed: false,
      inbound_allowed: false,
      administration: "ssm-only"
    },
    bootstrap: {
      bootstrap_sha256: $identity.bootstrap_sha256,
      toolchain_lock_sha256: $identity.toolchain_lock_sha256,
      payload_sha256: $identity.bootstrap_payload_sha256,
      apt_snapshot_id: $identity.apt_snapshot_id,
      packages: $packages
    },
    toolchain: {
      aws_cli: $aws_cli_version,
      buildkit: $buildkit_version,
      cargo_deny: $cargo_deny_version,
      cargo_machete: $cargo_machete_version,
      docker: $docker_version,
      rust: $rust_version,
      ssm_agent: $ssm_agent_version
    },
    source_policy: {
      repository: $identity.source_repository_identity,
      delivery_mode: $identity.source_delivery_mode,
      source_bucket: $identity.source_bucket,
      source_kms_alias_arn: $identity.source_kms_alias_arn,
      exact_commit_sha_required: true,
      manifest_digest_required: true,
      bundle_digest_required: true,
      ref_allowed: false,
      dirty_tree_allowed: false,
      build_host_github_credential: false,
      manifest_prefix: "source/manifests/sha256/",
      bundle_prefix: "source/bundles/sha256/",
      submodules_allowed: false,
      gitlinks_allowed: false,
      git_lfs_allowed: false,
      root_verified_and_published: true
    },
    publication: {
      bucket: $identity.artifact_bucket,
      prefixes: ["artifacts/sha256/", "evidence/sha256/"],
      read_allowed: false,
      kms_alias_arn: $identity.artifact_kms_alias_arn
    }
  }' > /var/lib/cats-build/readiness-v1.json
chmod 0444 /var/lib/cats-build/readiness-v1.json
/usr/local/bin/cats-verify-build-host-readiness >/dev/null
