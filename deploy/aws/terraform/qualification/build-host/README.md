# Qualification build host

Status: registered independent qualification asset. Verify live identity/readiness before each run,
then use it for exact-SHA native Linux build/test and retain its immutable receipts; it is evidence
infrastructure, not a production authority.

This stack owns an isolated, production-account qualification build cell. The
build host has no GitHub credential. A trusted controller outside the host
turns one clean exact Cats commit into a content-addressed Git bundle and
manifest, then conditionally creates those objects in the dedicated source
bucket under its dedicated KMS key.

## Publish exact source from the controller

Resolve the source bucket and key from recovered, reviewed Terraform outputs or the approved
qualification inventory. Do not run `terraform output`, plan or apply from an empty state directory.
Use pre-existing private work and evidence directories; the helper does not change their modes. The
caller account, bucket account and KMS-key account must all equal the explicit reviewed account.

```sh
bash deploy/aws/terraform/qualification/build-host/tools/publish-source-bundle.sh \
  "$QUALIFICATION_AWS_ACCOUNT_ID" \
  /trusted/clean/cats \
  "$EXACT_40_HEX_COMMIT" \
  "$SOURCE_BUCKET_NAME" \
  "$SOURCE_KMS_ALIAS_ARN" \
  /approved/private-work \
  /approved/evidence/source-bundle.json
```

The controller rejects a dirty checkout, branch/tag input, an unexpected
origin, submodules, gitlinks and Git LFS pointers. Bundle and manifest keys are
their SHA-256 digests. Upload uses `If-None-Match: *`, an S3 SHA-256 checksum
and the exact source KMS key; an existing key is accepted only when HEAD proves
the same bytes, encryption and version. Source-object deletion is denied by
bucket policy.

## Deliver and build

Run source delivery as root through SSM, passing only the three immutable
identifiers printed by the controller helper:

```sh
cats-checkout-exact-sha \
  "$EXACT_40_HEX_COMMIT" "$MANIFEST_SHA256" "$BUNDLE_SHA256"
```

The launcher downloads only the two digest-derived keys, validates manifest
shape, S3 version/checksum/encryption, bundle bytes/size, bundle ref, commit and
tree, and expands in a fresh root-only Git repository with system/global
configuration and hooks disabled. Publication and its stable receipt are one
rollback-safe operation. Source, Git administrative data, the active-delivery
marker and receipts are root-owned read-only; `cats-build` cannot replace or
unlink them.

Build jobs are launched by the root-only orchestrator and receive a new HOME,
Cargo home, target and output directory every time:

```sh
cats-run-build \
  "$EXACT_40_HEX_COMMIT" "$MANIFEST_SHA256" "$BUNDLE_SHA256" \
  --with-postgres -- ./scripts/quality.sh full
```

The reusable Rust toolchain and quality-gate binaries are root-owned and
non-writable. The build process has no AWS environment, cannot reach IMDS, and
cannot access the root Docker or BuildKit sockets. `quality.sh full` runs
natively on this x86_64 Linux host and therefore covers Linux-only code while
also running the dependency gates. Do not use `quality.sh linux` here: that
Docker compatibility entry point exists for macOS or foreign-architecture
workstations and would require handing the candidate build a daemon socket.
The trusted bootstrap/readiness container probes use bridge networking, and
the host FORWARD policy denies IMDS.

The job environment grants Git trust only to the exact frozen
`/srv/cats-build/source` path and disables optional Git locks. It never changes
repository ownership, persists a global/system Git setting or uses a wildcard
`safe.directory`; filesystem permissions remain the write-authority boundary.

`quality.sh test/full` owns the native test-process contract. It removes a low inherited soft
open-file cap by raising it to the job's existing hard limit and fixes Rust's test harness at four
threads. On Linux it also adds the standard `/usr/sbin` lookup path without changing the inherited
tool priority, then requires the `mkfs.ext4`, `debugfs` and `e2fsck` tools supplied by the pinned
`e2fsprogs` package. The isolated runner retains the job hard ceiling; the Docker Linux gate makes
the same resource and package contract explicit. This keeps high-core qualification Hosts
deterministic without changing Host-wide limits or hiding settings in an operator shell.

The candidate uid 2000 may write a regular file only inside its per-job `output/` directory. After
the job exits, the root orchestrator freezes that output as root-owned and non-writable and records
the Host-local immutable receipt. `cats-run-build` does not publish it. To retain a selected frozen
log in the append-only evidence bucket, a trusted root operator separately runs:

```sh
cats-publish-content-addressed evidence <frozen-output-file>
```

The publisher accepts only the frozen form. It opens every path component with `O_NOFOLLOW`, copies
from the held file descriptor into root-only staging, and uploads one content-addressed object.

## Trusted native manual release

The Docker/Guest manual release is a separate root/operator lane. It does not run as `cats-build`
and does not weaken that candidate uid's Docker, BuildKit, sudo, AWS or IMDS isolation. After the
same exact source delivery, the trusted operator prepares one versioned tool root, verifies it, and
builds the exporter output:

```sh
/bin/bash /srv/cats-build/source/deploy/aws/terraform/qualification/build-host/tools/manual-release-host.sh \
  prepare "$EXACT_40_HEX_COMMIT" "$MANIFEST_SHA256" "$BUNDLE_SHA256" \
  "$CONTROL_IMAGE_REFERENCE" "$GATEWAY_IMAGE_REFERENCE"
/bin/bash /srv/cats-build/source/deploy/aws/terraform/qualification/build-host/tools/manual-release-host.sh \
  verify "$EXACT_40_HEX_COMMIT" "$MANIFEST_SHA256" "$BUNDLE_SHA256" \
  "$CONTROL_IMAGE_REFERENCE" "$GATEWAY_IMAGE_REFERENCE"
/bin/bash /srv/cats-build/source/deploy/aws/terraform/qualification/build-host/tools/manual-release-host.sh \
  build "$EXACT_40_HEX_COMMIT" "$MANIFEST_SHA256" "$BUNDLE_SHA256" \
  "$CONTROL_IMAGE_REFERENCE" "$GATEWAY_IMAGE_REFERENCE"
```

`prepare` is the only mutating Host step. It accepts only the existing reviewed Ubuntu snapshot,
installs exact Guest-builder package versions, and installs digest-pinned Buildx plus the repository's
exact Rust toolchain and musl target under a lock-digest path in `/opt/cats-manual-release/`. It never
changes the `cats-build` uid or its frozen toolchain. `verify` is read-only. `build` uses a fresh
Docker config with no registry credentials, calls `build-manual-release.sh --export-images`, and
never accepts `--push`. The two explicit references are the reviewed production ECR
`repository:tag` values frozen into the release manifest; naming an ECR repository does not contact
it during the OCI export.

The build output and log are frozen below the ordinary per-source per-job target. The runner writes
the ordinary immutable build receipt in `/var/lib/cats-build/build-receipts/`, so the existing
publisher can retain the transport archive without a new artifact authority:

```sh
cats-publish-content-addressed artifacts \
  /srv/cats-build/target/$EXACT_40_HEX_COMMIT-$MANIFEST_SHA256-$BUNDLE_SHA256/\
$JOB_ID/output/cats-manual-release-$EXACT_40_HEX_COMMIT.tar.zst
```

Do not run `prepare` until the exact source, helper SHA-256 and
`manual-release-toolchain-lock-v1.json` versions have been reviewed. Do not retry a timed-out build:
retain the SSM command id and inspect the immutable receipt/output first.

## Reuse preflight and retry boundary

Run one fail-fast preflight for the whole build:

1. authenticate once, then verify the reviewed AWS account and `us-east-1`; an expired session means
   inventory is unknown, not absent;
2. require a clean 40-hex commit and `quality.sh provenance` with the same HEAD and `dirty=false`;
3. resolve exactly one running Host by the full qualification tags, require SSM Online, versioned
   source bucket and enabled KMS key;
4. send `cats-verify-build-host-readiness` once and require its account/region/namespace/cell/x86_64
   identity to match;
5. publish one source bundle, then submit checkout and build as one SSM command.

Poll that command with `get-command-invocation` until a service terminal state. The stock
`aws ssm wait command-executed` window is shorter than a normal full build. A local polling timeout,
expired login or failed readiness probe retains the command ID and stops the run; it never submits a
second build or starts/replaces infrastructure.

`AWS-RunShellScript` starts commands with `/bin/sh`. A diagnostic that needs Bash semantics must
enter `/bin/bash` explicitly; a failure before the calibrated positive control says nothing about
the Host state. Controller-side orchestration also uses an explicit Bash shell so zsh reserved names
cannot change command behavior.
