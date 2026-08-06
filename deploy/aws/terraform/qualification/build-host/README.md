# Qualification build host

This stack owns an isolated, production-account qualification build cell. The
build host has no GitHub credential. A trusted controller outside the host
turns one clean exact Cats commit into a content-addressed Git bundle and
manifest, then conditionally creates those objects in the dedicated source
bucket under its dedicated KMS key.

## Publish exact source from the controller

The source bucket and key are Terraform outputs. Use pre-existing private work
and evidence directories; the helper does not change their modes. The caller
account, bucket account and KMS-key account must all equal the explicit
reviewed account argument.

```sh
./tools/publish-source-bundle.sh \
  "$QUALIFICATION_AWS_ACCOUNT_ID" \
  /trusted/clean/cats \
  "$EXACT_40_HEX_COMMIT" \
  "$(terraform output -raw source_bucket_name)" \
  "$(terraform output -raw source_kms_alias_arn)" \
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

The candidate uid 2000 may write a regular file only inside its per-job
`output/` directory. After the job exits, the root orchestrator freezes that
output as root-owned and non-writable; the publisher accepts only this frozen
form. It opens every path component with `O_NOFOLLOW`, copies from the held file
descriptor into root-only staging, and then uploads to the append-only artifact
bucket.
