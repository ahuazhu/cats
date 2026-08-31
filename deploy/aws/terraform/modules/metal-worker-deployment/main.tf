data "aws_partition" "current" {}

locals {
  resource_name = "${var.name_prefix}-${var.environment}-worker"
  artifact_key  = "worker/${var.worker_bundle_sha256}/cats-worker.tar.zst"
  tags = merge(var.tags, {
    Component   = "metal-worker-deployment"
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = "Cats"
  })

  # Non-secret worker configuration, used only to seed a host that has no
  # worker.env yet. Secrets never appear here: they arrive through Secrets
  # Manager and are merged over this by the overlay below.
  worker_base_environment = join("\n", concat(
    [
      for key in sort(keys(var.worker_base_environment)) :
      "${key}=${var.worker_base_environment[key]}"
    ],
    [
      "CATS_CHUNKSTORE_PREFIX=${var.chunkstore_prefix}",
      "CATS_POSTGRES_SCHEMA=${var.control_postgres_schema}",
    ],
  ))

  # Non-secret configuration Terraform owns outright, merged onto an existing
  # worker.env on every deployment rather than only seeding a new one.
  #
  # worker_base_environment cannot carry these: it is written once and then
  # left alone so operator edits survive, which means a key added to it never
  # reaches a host that already has the file. The DSN source has to reach one.
  worker_managed_environment = join("\n", concat(
    [
      for key in sort(keys(var.worker_managed_environment)) :
      "${key}=${var.worker_managed_environment[key]}"
    ],
    [
      "CATS_CHUNKSTORE_PREFIX=${var.chunkstore_prefix}",
      "CATS_POSTGRES_SCHEMA=${var.control_postgres_schema}",
    ],
    var.database_master_user_secret_arn == null ? [] : [
      "CATS_POSTGRES_SECRET_ARN=${var.database_master_user_secret_arn}",
    ],
  ))

  deployment_script = <<-SCRIPT
    set -eu

    # The association assumed the AWS CLI was already on the host. A stock
    # Ubuntu 24.04 AMI has neither the CLI nor an awscli apt candidate, so a
    # freshly launched worker failed here with "aws: not found" before it ever
    # reached the bundle. Bootstrap it once; an already-provisioned host skips
    # straight through.
    export PATH="/usr/local/bin:$PATH"
    export DEBIAN_FRONTEND=noninteractive

    if ! command -v aws >/dev/null 2>&1; then
      if ! command -v unzip >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -qy --no-install-recommends unzip
      fi
      cli_stage="$(mktemp -d /var/tmp/awscli.XXXXXX)"
      curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "$cli_stage/awscliv2.zip"
      unzip -q "$cli_stage/awscliv2.zip" -d "$cli_stage"
      "$cli_stage/aws/install" --update
      rm -rf -- "$cli_stage"
    fi

    if ! command -v zstd >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -qy --no-install-recommends zstd
    fi

    if ! command -v jq >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -qy --no-install-recommends jq
    fi

    # jq was already being used below without ever being checked for. It is
    # also what render-postgres-url uses to read the managed secret.
    # curl talks to IMDS when a fresh host derives its advertise address.
    for required in aws jq zstd tar sha256sum findmnt curl base64 cmp flock stat systemd-run systemctl journalctl timeout python3 readlink; do
      command -v "$required" >/dev/null 2>&1 || {
        echo "worker deployment needs $required on the host" >&2
        exit 1
      }
    done

    artifact_path="/var/tmp/cats-worker-${var.worker_bundle_sha256}.tar.zst"
    stage_path="$(mktemp -d /var/tmp/cats-worker-stage.XXXXXX)"
    runtime_secret=""
    runtime_overlay=""
    environment_temp=""
    seed_temp=""
    archive_entries=""
    release_transaction_active=0
    release_installer=""
    cleanup() {
      status=$?
      trap - EXIT INT TERM
      if [ "$release_transaction_active" -eq 1 ]; then
        systemctl mask --runtime cats-worker >/dev/null 2>&1 || true
        cats_stop_node_service cats-worker >/dev/null 2>&1 || true
        "$release_installer" rollback >/dev/null 2>&1 || true
      fi
      rm -rf -- "$stage_path"
      rm -f -- "$artifact_path"
      for temporary_path in "$runtime_secret" "$runtime_overlay" "$environment_temp" "$seed_temp" "$archive_entries"; do
        if [ -n "$temporary_path" ]; then
          rm -f -- "$temporary_path"
        fi
      done
      exit "$status"
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    aws s3 cp --no-progress "s3://${aws_s3_bucket.artifacts.id}/${aws_s3_object.worker_bundle.key}" "$artifact_path"
    echo "${var.worker_bundle_sha256}  $artifact_path" | sha256sum --check --strict -
    archive_entries="$(mktemp /var/tmp/cats-worker-entries.XXXXXX)"
    tar --zstd -tf "$artifact_path" > "$archive_entries"
    awk '
      /^\// || /(^|\/)\.\.($|\/)/ { exit 1 }
      seen[$0]++ { exit 1 }
    ' "$archive_entries"
    tar --zstd -tvf "$artifact_path" | awk 'substr($1,1,1) !~ /^[-d]$/ { exit 1 }'
    tar --zstd -xf "$artifact_path" -C "$stage_path"
    . "$stage_path/worker-deployment-transaction.sh"
    "$stage_path/install-guest-runtime-release.sh" verify \
      "$stage_path/guest-runtime-release.v1"
    # The validator is itself part of the digest-checked, preflighted bundle.
    # Do not execute anything from the empty mktemp stage before extraction.
    # Identity validation still precedes the idle check, service stop, or any
    # installed-file mutation.
    "$stage_path/validate-node-identity-installation.sh"

    # One Host-global open-file-description lock spans the entire mutation,
    # candidate start/readiness proof, and commit/rollback boundary.
    test "${var.install_root}" = /opt/cats
    # Host-lifetime prerequisites come from the host bootstrap, not this
    # release transaction. cats-worker.service consumes both at start; fail
    # here on a fresh host instead of crash-looping the unit later.
    test -s /etc/cats/rds-ca.pem
    test -x "${var.install_root}/bin/cloud-hypervisor"
    release_installer="${var.install_root}/bin/install-guest-runtime-release"
    cats_acquire_worker_deployment_lock

    # Before publishing an activation journal, close both ways the cached old
    # unit could start: a runtime mask covers this boot, while the fsynced new
    # unit/recovery helper covers a reboot. Only then may prepare expose a
    # candidate release identity. Prove physical idle immediately before the
    # masked stop.
    cgroup_v2_root="$(cats_worker_cgroup_v2_root)"
    "$stage_path/require-idle-worker.sh" \
      "$cgroup_v2_root" "${var.install_root}/bin" "${var.install_root}/bin/cloud-hypervisor"
    cats_gate_node_service cats-worker
    cats_worker_deployment_crash_probe after-mask-worker

    install -D -m 0755 "$stage_path/install-guest-runtime-release.sh" "$release_installer"
    cats_worker_deployment_crash_probe after-install-release-installer
    install -D -m 0755 "$stage_path/worker-deployment-transaction.sh" "${var.install_root}/bin/worker-deployment-transaction"
    cats_worker_deployment_crash_probe after-install-deployment-transaction
    install -m 0644 "$stage_path/cats-worker.service" /etc/systemd/system/cats-worker.service
    cats_worker_deployment_crash_probe after-install-worker-unit
    sync -f "$release_installer"
    sync -f "${var.install_root}/bin/worker-deployment-transaction"
    sync -f "${var.install_root}/bin"
    sync -f /etc/systemd/system/cats-worker.service
    sync -f /etc/systemd/system
    cats_worker_deployment_crash_probe after-fsync-worker-recovery-gate
    systemctl daemon-reload
    cats_worker_deployment_crash_probe after-recovery-gate-daemon-reload

    release_transaction_active=1
    "$release_installer" prepare "$stage_path/guest-runtime-release.v1"
    cats_worker_deployment_crash_probe after-installer-return

    # The fixed receipt describes the currently installed bytes. Invalidate an
    # older receipt before the first binary replacement so a crash cannot leave
    # stale evidence claiming that the previous bundle is still installed.
    worker_installation_receipt="${var.install_root}/release/worker-installation-receipt.v1.json"
    rm -f -- "$worker_installation_receipt"
    sync -f "${var.install_root}/release"
    cats_worker_deployment_crash_probe after-invalidate-worker-installation-receipt

    # -D creates the parent directory. Without it a host that has never been
    # touched by install.sh fails here: /opt/cats/bin does not exist yet, and
    # the association only ever ran against hosts that had been set up by hand.
    install -D -m 0755 "$stage_path/cats" "${var.install_root}/bin/cats"
    cats_worker_deployment_crash_probe after-install-cats-cli
    install -D -m 0755 "$stage_path/cats-noded" "${var.install_root}/bin/cats-noded"
    cats_worker_deployment_crash_probe after-install-cats-noded
    install -D -m 0755 "$stage_path/cats-usage-schema-v16-verifier" "${var.install_root}/bin/cats-usage-schema-v16-verifier"
    cats_worker_deployment_crash_probe after-install-cats-usage-schema-v16-verifier
    install -D -m 0755 "$stage_path/cats-usage-terminal-receipt-verifier" "${var.install_root}/bin/cats-usage-terminal-receipt-verifier"
    cats_worker_deployment_crash_probe after-install-cats-usage-terminal-receipt-verifier
    install -D -m 0755 "$stage_path/cats-blockd" "${var.install_root}/bin/cats-blockd"
    cats_worker_deployment_crash_probe after-install-cats-blockd
    install -D -m 0755 "$stage_path/cats-guest-agent" "${var.install_root}/bin/cats-guest-agent"
    cats_worker_deployment_crash_probe after-install-cats-guest-agent
    install -D -m 0755 "$stage_path/cats-e3-guest-workload" "${var.install_root}/bin/cats-e3-guest-workload"
    cats_worker_deployment_crash_probe after-install-cats-e3-guest-workload
    install -D -m 0755 "$stage_path/update-guest-seed.sh" "${var.install_root}/bin/update-guest-seed"
    cats_worker_deployment_crash_probe after-install-guest-seed-updater
    install -D -m 0755 "$stage_path/require-idle-worker.sh" "${var.install_root}/bin/require-idle-worker"
    cats_worker_deployment_crash_probe after-install-idle-guard
    install -D -m 0755 "$stage_path/render-postgres-url.sh" "${var.install_root}/bin/render-postgres-url"
    cats_worker_deployment_crash_probe after-install-postgres-renderer
    install -D -m 0755 "$stage_path/setup-guest-network.sh" "${var.install_root}/bin/setup-guest-network"
    cats_worker_deployment_crash_probe after-install-guest-network-setup
    install -m 0644 "$stage_path/cats-postgres-url.service" /etc/systemd/system/cats-postgres-url.service
    cats_worker_deployment_crash_probe after-install-postgres-unit
    install -m 0644 "$stage_path/cats-postgres-url.timer" /etc/systemd/system/cats-postgres-url.timer
    cats_worker_deployment_crash_probe after-install-postgres-timer

    # The Agent opens the runtime socket roots, the identity-selected state
    # namespaces and the Host lock; it creates none of them, so a Host that
    # never ran this provisioner cannot start the release at all. The
    # provisioner reads the installed identity, which step 5 published before
    # this deployment ran.
    install -D -o root -g root -m 0644 "$stage_path/cats-vmm.conf" \
      /usr/lib/tmpfiles.d/cats-vmm.conf
    cats_worker_deployment_crash_probe after-install-runtime-tmpfiles
    install -D -o root -g root -m 0755 \
      "$stage_path/provision-vmm-socket-namespaces.sh" \
      "${var.install_root}/bin/provision-vmm-socket-namespaces"
    "${var.install_root}/bin/provision-vmm-socket-namespaces"
    cats_worker_deployment_crash_probe after-provision-vmm-socket-namespaces

    curl_path="$(readlink -f "$(command -v curl)")"
    systemctl_path="$(readlink -f "$(command -v systemctl)")"
    journalctl_path="$(readlink -f "$(command -v journalctl)")"
    timeout_path="$(readlink -f "$(command -v timeout)")"
    sync -f "${var.install_root}/bin"
    python3 - \
      "$worker_installation_receipt" \
      "sha256:${var.worker_bundle_sha256}" \
      "${var.install_root}" \
      "$curl_path" "$systemctl_path" "$journalctl_path" "$timeout_path" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


def same_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_uid,
        left.st_gid,
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_gid,
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def fingerprint(path: Path, *, installed_member: bool) -> dict[str, object]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size <= 0:
        raise SystemExit(f"receipt input is not a non-empty regular file: {path}")
    if before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode) & 0o022:
        raise SystemExit(f"receipt input is not root-owned and write-protected: {path}")
    if installed_member and (
        before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o755
    ):
        raise SystemExit(f"installed worker member metadata is invalid: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not same_metadata(before, opened):
            raise SystemExit(f"receipt input changed before read: {path}")
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise SystemExit(f"receipt input ended during read: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SystemExit(f"receipt input grew during read: {path}")
        if installed_member:
            os.fsync(descriptor)
        after = os.fstat(descriptor)
        if not same_metadata(opened, after):
            raise SystemExit(f"receipt input changed during read: {path}")
    finally:
        os.close(descriptor)
    return {
        "path": str(path),
        "sha256": "sha256:" + digest.hexdigest(),
        "size_bytes": before.st_size,
    }


if os.geteuid() != 0:
    raise SystemExit("worker installation receipt must be written by root")
receipt_path = Path(sys.argv[1])
bundle_digest = sys.argv[2]
install_root = Path(sys.argv[3])
if re.fullmatch(r"sha256:[0-9a-f]{64}", bundle_digest) is None:
    raise SystemExit("worker bundle digest is invalid")

member_names = (
    "cats",
    "cats-noded",
    "cats-usage-schema-v16-verifier",
    "cats-usage-terminal-receipt-verifier",
    "cats-blockd",
    "cats-guest-agent",
    "cats-e3-guest-workload",
)
members = {
    name: fingerprint(install_root / "bin" / name, installed_member=True)
    for name in member_names
}
host_tool_names = ("curl", "systemctl", "journalctl", "timeout")
host_tools = {
    name: fingerprint(Path(path), installed_member=False)
    for name, path in zip(host_tool_names, sys.argv[4:8])
}
receipt = {
    "host_tools": host_tools,
    "members": members,
    "service": "cats-worker.service",
    "version": 1,
    "worker_bundle_sha256": bundle_digest,
}
raw = json.dumps(
    receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")
).encode("utf-8")

receipt_parent_metadata = receipt_path.parent.lstat()
if (
    not stat.S_ISDIR(receipt_parent_metadata.st_mode)
    or stat.S_ISLNK(receipt_parent_metadata.st_mode)
    or receipt_parent_metadata.st_uid != 0
    or receipt_parent_metadata.st_gid != 0
    or stat.S_IMODE(receipt_parent_metadata.st_mode) & 0o022
):
    raise SystemExit("worker installation receipt parent is not a protected real directory")
temporary_descriptor, temporary_name = tempfile.mkstemp(
    prefix=".worker-installation-receipt.", dir=receipt_path.parent
)
try:
    os.fchmod(temporary_descriptor, 0o600)
    os.fchown(temporary_descriptor, 0, 0)
    view = memoryview(raw)
    while view:
        written = os.write(temporary_descriptor, view)
        if written <= 0:
            raise OSError("short write while publishing worker installation receipt")
        view = view[written:]
    os.fsync(temporary_descriptor)
    os.close(temporary_descriptor)
    temporary_descriptor = -1
    os.replace(temporary_name, receipt_path)
    directory_descriptor = os.open(
        receipt_path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
except BaseException:
    if temporary_descriptor >= 0:
        os.close(temporary_descriptor)
    try:
        os.unlink(temporary_name)
    except FileNotFoundError:
        pass
    raise
PY
    cats_worker_deployment_crash_probe after-publish-worker-installation-receipt

    runtime_secret="$(mktemp /var/tmp/cats-worker-runtime.XXXXXX)"
    runtime_overlay="$(mktemp /var/tmp/cats-worker-overlay.XXXXXX)"
    aws secretsmanager get-secret-value \
      --secret-id "${aws_secretsmanager_secret.worker_runtime.arn}" \
      --query SecretString \
      --output text > "$runtime_secret"
    chmod 0600 "$runtime_secret"
    jq -er '
      if (keys - ["CATS_AUTH_TOKEN", "CATS_POSTGRES_URL"]) != [] or
         (.CATS_AUTH_TOKEN | type != "string" or length < 16) then
        error("unexpected worker runtime secret keys")
      else
        [to_entries[] | "\(.key)=\(.value)"] | join("\n")
      end
    ' "$runtime_secret" > "$runtime_overlay"

    # Registration is explicit in the direct protocol. Cross-check the
    # provisioned identity against IMDS before publishing any per-Host values
    # into the root-only environment file.
    imds_token="$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
      http://169.254.169.254/latest/api/token)"
    identity_document="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" \
      http://169.254.169.254/latest/dynamic/instance-identity/document)"
    identity_node_id="$(jq -er '.node_id' /etc/cats/identity/node-identity.v1.json)"
    semantic_node_id="node_$identity_node_id"
    identity_instance="$(jq -er '.immutable_host_id' /etc/cats/identity/node-identity.v1.json)"
    identity_vendor="$(jq -er '.provider_scope.provider' /etc/cats/identity/node-identity.v1.json)"
    identity_region="$(jq -er '.provider_scope.region' /etc/cats/identity/node-identity.v1.json)"
    instance_id="$(printf '%s' "$identity_document" | jq -er '.instanceId')"
    node_region="$(printf '%s' "$identity_document" | jq -er '.region')"
    node_zone="$(printf '%s' "$identity_document" | jq -er '.availabilityZone')"
    machine_type="$(printf '%s' "$identity_document" | jq -er '.instanceType')"
    private_ip="$(printf '%s' "$identity_document" | jq -er '.privateIp')"
    [ "$identity_vendor" = aws ]
    [ "$identity_instance" = "$instance_id" ]
    [ "$identity_region" = "$node_region" ]
    node_cpu="$(nproc)"
    node_memory="$(awk '/^MemTotal:/ { printf "%.0f\n", $2 * 1024; found=1 } END { if (!found) exit 1 }' /proc/meminfo)"
    printf '%s\n' \
      "CATS_NODE_ID=$semantic_node_id" \
      "CATS_NODE_NAME=__CATS_WORKER_NAME__" \
      "CATS_NODE_VENDOR=$identity_vendor" \
      "CATS_NODE_REGION=$node_region" \
      "CATS_NODE_ZONE=$node_zone" \
      "CATS_NODE_INSTANCE_ID=$instance_id" \
      "CATS_NODE_MACHINE_TYPE=$machine_type" \
      "CATS_NODE_CONTROL_ENDPOINT=http://$private_ip:7301" \
      "CATS_NODE_TOTAL_CPU=$node_cpu" \
      "CATS_NODE_TOTAL_MEMORY=$node_memory" >> "$runtime_overlay"

    # Terraform-owned non-secret keys are merged the same way, so they reach a
    # host that already has a worker.env instead of only seeding a new one.
    # sed rather than grep: with nothing to merge, grep would exit non-zero and
    # take the whole association down under `set -e`.
    sed '/^$/d' >> "$runtime_overlay" <<'CATS_MANAGED_ENVIRONMENT'
${local.worker_managed_environment}
CATS_MANAGED_ENVIRONMENT

    # The overlay merges onto an existing worker.env. A host that has never run
    # install.sh has no such file and awk died on it, so nothing in the
    # production path ever created the non-secret half of the configuration.
    # Seed it once; an existing file is left alone so operator edits survive.
    if [ ! -f "${var.worker_environment_file}" ]; then
      # Identity is never environment or IMDS data. The provisioner must have
      # installed the closed /etc/cats/identity artifact before this release.
      seed_temp="$(mktemp /var/tmp/cats-worker-seed.XXXXXX)"
      cat > "$seed_temp" <<'CATS_BASE_ENVIRONMENT'
${local.worker_base_environment}
CATS_BASE_ENVIRONMENT

      mkdir -p "$(dirname "${var.worker_environment_file}")"
      install -o root -g root -m 0600 "$seed_temp" "${var.worker_environment_file}"
      cats_worker_deployment_crash_probe after-install-worker-environment-seed
    fi

    environment_temp="$(mktemp /var/tmp/cats-worker-env.XXXXXX)"
    awk '
      NR == FNR {
        key = $0
        sub(/=.*/, "", key)
        replacement[key] = $0
        order[++replacement_count] = key
        next
      }
      {
        key = $0
        sub(/=.*/, "", key)
        if (key in replacement) {
          print replacement[key]
          replaced[key] = 1
        } else {
          print
        }
      }
      END {
        for (position = 1; position <= replacement_count; position++) {
          key = order[position]
          if (!(key in replaced)) {
            print replacement[key]
          }
        }
      }
    ' "$runtime_overlay" "${var.worker_environment_file}" > "$environment_temp"
    install -o root -g root -m 0600 "$environment_temp" "${var.worker_environment_file}"
    cats_worker_deployment_crash_probe after-install-worker-environment

    # Replace the golden RootDisk while the worker remains stopped. No create
    # can observe a new seed under an in-memory ID computed from the old bytes.
    "${var.install_root}/bin/update-guest-seed" \
      "${var.install_root}/guest/rootfs.ext4" \
      "$stage_path/cats-guest-agent" \
      "$stage_path/guest-systemd"
    cats_worker_deployment_crash_probe after-update-guest-seed

    systemctl daemon-reload
    cats_worker_deployment_crash_probe after-daemon-reload

    # The timer covers a rotation that happens while the worker keeps running.
    # cats-worker renders the DSN itself before every start, so this is not on
    # the startup path; `--now` also proves the renderer works on this host
    # before the worker is stopped, rather than after it fails to come back.
    systemctl enable --now cats-postgres-url.timer
    cats_worker_deployment_crash_probe after-enable-postgres-timer
    systemctl start cats-postgres-url.service
    cats_worker_deployment_crash_probe after-start-postgres-renderer

    cats_begin_candidate_lifetime cats-worker "$release_installer"
    cats_worker_deployment_crash_probe after-authorize-worker-start
    cats_ungate_node_service cats-worker
    cats_worker_deployment_crash_probe after-unmask-worker
    systemctl start cats-worker
    cats_worker_deployment_crash_probe after-start-worker
    cats_bind_candidate_main cats-worker "$release_installer"
    cats_worker_deployment_crash_probe after-bind-worker-main
    cats_wait_for_registered_node cats-worker
    cats_worker_deployment_crash_probe after-registration-readiness
    cats_commit_candidate "$release_installer"
    release_transaction_active=0
    cats_worker_deployment_crash_probe after-release-commit
    echo "Semantic Control/Node worker installed from the scoped release bundle"
    "${var.install_root}/bin/cats-noded" --help | grep -q -- "--control-endpoint"
    "${var.install_root}/bin/cats-noded" --help | grep -q -- "--host-lock"
    "${var.install_root}/bin/cats-noded" --help | grep -q -- "--blockd-socket-root"
    ! "${var.install_root}/bin/cats-noded" --help | grep -q -- "--runtime-cgroup-root"
    ! "${var.install_root}/bin/cats-noded" --help | grep -q -- "--guest-agent-bin"
    ! "${var.install_root}/bin/cats-noded" --help | grep -q -- "--metering-cgroup-root"
    # Secret version ${aws_secretsmanager_secret_version.worker_runtime.version_id}
  SCRIPT
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = var.artifact_bucket_name
  force_destroy = false

  tags = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "artifacts_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_tls_only.json
}

resource "aws_s3_object" "worker_bundle" {
  bucket      = aws_s3_bucket.artifacts.id
  key         = local.artifact_key
  source      = var.worker_bundle_path
  source_hash = var.worker_bundle_sha256

  server_side_encryption = "AES256"

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_s3_bucket_ownership_controls.artifacts,
    aws_s3_bucket_server_side_encryption_configuration.artifacts,
  ]
}

resource "aws_secretsmanager_secret" "worker_runtime" {
  name                    = "${local.resource_name}-runtime"
  description             = "Root-only direct Control/Node service token and optional PostgreSQL compatibility value."
  recovery_window_in_days = 30

  tags = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "worker_runtime" {
  secret_id     = aws_secretsmanager_secret.worker_runtime.id
  secret_string = jsonencode(var.worker_runtime_secret_data)
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = var.instance_role_name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "artifact_reader" {
  statement {
    sid       = "ListWorkerArtifacts"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["worker/*"]
    }
  }

  statement {
    sid       = "ReadWorkerArtifacts"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.artifacts.arn}/worker/*"]
  }

  statement {
    sid       = "WriteSsmOutput"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/ssm-output/*"]
  }

  statement {
    sid       = "ReadWorkerRuntimeSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.worker_runtime.arn]
  }

  # render-postgres-url reads the database password from the one place that
  # holds the current one. Scoped to that secret; the worker gets no broader
  # Secrets Manager access.
  dynamic "statement" {
    for_each = var.database_master_user_secret_arn == null ? [] : [var.database_master_user_secret_arn]

    content {
      sid       = "ReadDatabaseMasterUserSecret"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_policy" "artifact_reader" {
  name        = "${local.resource_name}-artifact-reader"
  description = "Read immutable Cats worker bundles and write SSM deployment output."
  policy      = data.aws_iam_policy_document.artifact_reader.json
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "artifact_reader" {
  role       = var.instance_role_name
  policy_arn = aws_iam_policy.artifact_reader.arn
}

# One association per worker rather than one association targeting the fleet:
# an association re-runs its script whenever it is created or updated, and
# require-idle-worker only lets that run on a drained host. Per-worker
# associations keep the blast radius to one host and let deploy_instances roll
# a release across a serving fleet one drained worker at a time.
resource "aws_ssm_association" "worker_deploy" {
  for_each = (
    var.deploy_instances == null
    ? var.instances
    : { for name in var.deploy_instances : name => var.instances[name] }
  )

  name             = "AWS-RunShellScript"
  association_name = "${local.resource_name}-${each.key}-${substr(var.worker_bundle_sha256, 0, 12)}"

  parameters = {
    # The script is shared across the fleet except for the one line where a
    # fresh host learns who it is.
    commands = replace(local.deployment_script, "__CATS_WORKER_NAME__", each.key)
  }

  targets {
    key    = "InstanceIds"
    values = [each.value]
  }

  output_location {
    s3_bucket_name = aws_s3_bucket.artifacts.id
    s3_key_prefix  = "ssm-output"
  }

  wait_for_success_timeout_seconds = 900

  lifecycle {
    # SSM caps AssociationName at 128 characters. The worker-key validation
    # bounds only its own part; name_prefix and environment are unrestricted.
    precondition {
      condition     = length("${local.resource_name}-${each.key}-${substr(var.worker_bundle_sha256, 0, 12)}") <= 128
      error_message = "The association name (name_prefix-environment-worker-<name>-<sha12>) exceeds SSM's 128-character limit; shorten the worker name or name_prefix."
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm_core,
    aws_iam_role_policy_attachment.artifact_reader,
    aws_secretsmanager_secret_version.worker_runtime,
    aws_s3_object.worker_bundle,
  ]
}
