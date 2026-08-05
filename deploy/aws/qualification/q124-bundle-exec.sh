#!/usr/bin/env bash
# Enter the exact reviewed archive recorded by a recovered manifest.
set -euo pipefail
umask 077

die() { printf 'q124-bundle: %s\n' "$*" >&2; exit 1; }
manifest=${Q124_MANIFEST:?manifest path required}
[[ -f $manifest && ! -L $manifest ]] || die "manifest must be a regular non-symlink"
source_sha=$(jq -er '.bundle.source_sha | select(test("^[0-9a-f]{40,64}$"))' "$manifest") || die "invalid manifest source sha"
archive_key=$(jq -er '.bundle.archive_key | select(type == "string")' "$manifest") || die "invalid manifest archive key"
archive_sha=$(jq -er '.bundle.archive_sha256 | select(test("^[0-9a-f]{64}$"))' "$manifest") || die "invalid manifest archive digest"
orchestrator_sha=$(jq -er '.bundle.orchestrator_sha256 | select(test("^[0-9a-f]{64}$"))' "$manifest") || die "invalid orchestrator digest"
[[ $archive_key == "worker/qualification-124/$source_sha/q124-source-$archive_sha.tar.gz" ]] || die "archive key is not manifest-bound"

work=${Q124_BUNDLE_WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP required}/q124-reviewed-bundle}
[[ $work == /* && ! -e $work && ! -L $work ]] || die "bundle work directory must be a new absolute path"
install -d -m 0700 "$work"
archive=$work/source.tar.gz
if [[ -n ${Q124_BUNDLE_ARCHIVE:-} ]]; then
  [[ -f $Q124_BUNDLE_ARCHIVE && ! -L $Q124_BUNDLE_ARCHIVE ]] || die "bundle archive override must be a regular non-symlink"
  cp "$Q124_BUNDLE_ARCHIVE" "$archive"
else
  [[ ${Q124_ARTIFACT_BUCKET:-} =~ ^[a-z0-9][a-z0-9.-]+$ ]] || die "invalid artifact bucket"
  [[ ${Q124_REGION:-} =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]$ ]] || die "invalid region"
  aws --region "$Q124_REGION" s3 cp "s3://${Q124_ARTIFACT_BUCKET}/${archive_key}" "$archive" --only-show-errors \
    || die "reviewed archive download failed"
fi
actual=$(sha256sum "$archive" | awk '{print $1}')
[[ $actual == "$archive_sha" ]] || die "reviewed archive digest mismatch"

listing=$work/listing
tar -tzf "$archive" >"$listing" || die "reviewed archive listing failed"
while IFS= read -r entry; do
  [[ -n $entry && $entry != /* ]] || die "archive contains an absolute/empty path"
  stripped=${entry#./}
  [[ $stripped != .. && $stripped != ../* && $stripped != */../* && $stripped != */.. ]] || die "archive contains path traversal"
done <"$listing"
source_root=$work/source
install -d -m 0700 "$source_root"
tar -xzf "$archive" -C "$source_root" --no-same-owner || die "reviewed archive extraction failed"
orchestrator=$source_root/deploy/aws/qualification/q124-temp-worker.sh
[[ -f $orchestrator && ! -L $orchestrator ]] || die "reviewed orchestrator is missing"
actual=$(sha256sum "$orchestrator" | awk '{print $1}')
[[ $actual == "$orchestrator_sha" ]] || die "reviewed orchestrator digest mismatch"
chmod 0755 "$orchestrator"
export Q124_BUNDLE_ROOT=$source_root
exec "$orchestrator" "$@"
