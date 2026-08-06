#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" != "0" ]]; then
  echo "artifact publication is root-mediated" >&2
  exit 77
fi

readonly identity_file="/etc/cats-build/identity.json"
readonly receipt_library="/usr/local/lib/cats-build/immutable-receipt.sh"
# shellcheck source=/dev/null
source "${receipt_library}"
if [[ $# -ne 2 || ! -f $2 || -L $2 ]]; then
  echo "usage: cats-publish-content-addressed <artifacts|evidence> <file>" >&2
  exit 64
fi

case "$1" in
  artifacts|evidence) readonly object_class="$1" ;;
  *) echo "object class must be artifacts or evidence" >&2; exit 65 ;;
esac
readonly source_file="$2"
readonly staging_dir="$(mktemp -d /var/lib/cats-build/publication.XXXXXX)"
cleanup() {
  rm -rf -- "${staging_dir}"
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "${staging_dir}"
readonly staged_file="${staging_dir}/payload"
readonly provenance="$(/usr/local/libexec/cats-build/stage-build-output "${source_file}" "${staged_file}")"
readonly job_id="$(jq -er '.job_id' <<<"${provenance}")"
readonly build_receipt="/var/lib/cats-build/build-receipts/${job_id}.json"
if [[ ! -f "${build_receipt}" || -L "${build_receipt}" || "$(stat --format='%u:%a' "${build_receipt}")" != "0:444" ]]; then
  echo "root-owned immutable build receipt is missing" >&2
  exit 65
fi
jq -e \
  --argjson provenance "${provenance}" \
  '.schema_version == 1 and
   .source_sha == $provenance.source_sha and
   .manifest_sha256 == $provenance.manifest_sha256 and
   .bundle_sha256 == $provenance.bundle_sha256 and
   .job_id == $provenance.job_id and
   .output_dir == ("/srv/cats-build/target/" + $provenance.source_sha + "-" +
     $provenance.manifest_sha256 + "-" + $provenance.bundle_sha256 + "/" +
     $provenance.job_id + "/output") and
   .output_frozen == true and .job_cgroup_drained == true' \
  "${build_receipt}" >/dev/null
if [[ "${object_class}" == "artifacts" && "$(jq -er '.exit_status' "${build_receipt}")" != "0" ]]; then
  echo "successful build receipt is required for artifact publication" >&2
  exit 65
fi
readonly source_size="$(stat --format='%s' "${staged_file}")"
readonly single_put_limit_bytes=5368709120
if (( source_size > single_put_limit_bytes )); then
  echo "file exceeds the explicit 5 GiB single-PutObject contract" >&2
  exit 66
fi
readonly digest="$(sha256sum "${staged_file}" | awk '{print $1}')"
readonly bucket="$(jq -er '.artifact_bucket' "${identity_file}")"
readonly account_id="$(jq -er '.account_id' "${identity_file}")"
readonly kms_alias_arn="$(jq -er '.artifact_kms_alias_arn' "${identity_file}")"
readonly kms_key_arn="$(
  aws kms describe-key \
    --key-id "${kms_alias_arn}" \
    --query 'KeyMetadata.Arn' \
    --output text
)"
if [[ ! "${kms_alias_arn}" =~ ^arn:aws:kms:[a-z0-9-]+:${account_id}:alias/cats-qualification-v2-build-artifacts$ ]] ||
   [[ ! "${kms_key_arn}" =~ ^arn:aws:kms:[a-z0-9-]+:${account_id}:key/[0-9a-f-]{36}$ ]]; then
  echo "artifact KMS identity differs from the reviewed alias" >&2
  exit 69
fi
readonly object_key="${object_class}/sha256/${digest}"
readonly checksum_sha256="$(python3 - "${staged_file}" <<'PY'
import base64
import hashlib
import pathlib
import sys

digest = hashlib.file_digest(pathlib.Path(sys.argv[1]).open("rb"), "sha256").digest()
print(base64.b64encode(digest).decode("ascii"))
PY
)"

readonly response="$(aws s3api put-object \
  --bucket "${bucket}" \
  --expected-bucket-owner "${account_id}" \
  --key "${object_key}" \
  --body "${staged_file}" \
  --checksum-algorithm SHA256 \
  --if-none-match '*' \
  --metadata "sha256=${digest}" \
  --server-side-encryption aws:kms \
  --ssekms-key-id "${kms_alias_arn}")"

jq -e \
  --arg checksum "${checksum_sha256}" \
  --arg kms_key_arn "${kms_key_arn}" \
  '.ChecksumSHA256 == $checksum and .ServerSideEncryption == "aws:kms" and .SSEKMSKeyId == $kms_key_arn and (.VersionId | type == "string" and length > 0)' \
  <<<"${response}" >/dev/null

jq -n -S \
  --arg bucket "${bucket}" \
  --arg key "${object_key}" \
  --arg checksum_sha256 "${checksum_sha256}" \
  --arg kms_alias_arn "${kms_alias_arn}" \
  --arg kms_key_arn "${kms_key_arn}" \
  --arg sha256 "${digest}" \
  --arg version_id "$(jq -er '.VersionId' <<<"${response}")" \
  --arg source_sha "$(jq -er '.source_sha' <<<"${provenance}")" \
  --arg manifest_sha256 "$(jq -er '.manifest_sha256' <<<"${provenance}")" \
  --arg bundle_sha256 "$(jq -er '.bundle_sha256' <<<"${provenance}")" \
  --arg job_id "${job_id}" \
  --arg output_relative_path "$(jq -er '.output_relative_path' <<<"${provenance}")" \
  --arg build_receipt "${build_receipt}" \
  --arg build_receipt_sha256 "$(sha256sum "${build_receipt}" | awk '{print $1}')" \
  '{schema_version: 1, bucket: $bucket, key: $key, sha256: $sha256, checksum_sha256: $checksum_sha256, server_side_encryption: "aws:kms", kms_alias_arn: $kms_alias_arn, kms_key_arn: $kms_key_arn, version_id: $version_id, source_sha: $source_sha, manifest_sha256: $manifest_sha256, bundle_sha256: $bundle_sha256, job_id: $job_id, output_relative_path: $output_relative_path, build_receipt: $build_receipt, build_receipt_sha256: $build_receipt_sha256}' \
  >"${staging_dir}/publication-receipt.json"

readonly publication_receipt_dir="/var/lib/cats-build/publication-receipts"
install -d -m 0755 -o root -g root "${publication_receipt_dir}"
readonly prepared_publication_receipt="$(mktemp "${publication_receipt_dir}/.${job_id}-${digest}.XXXXXX")"
install -m 0600 "${staging_dir}/publication-receipt.json" "${prepared_publication_receipt}"
readonly publication_receipt="${publication_receipt_dir}/${job_id}-${digest}.json"
write_immutable_receipt "${prepared_publication_receipt}" "${publication_receipt}"
chown root:root "${publication_receipt}"
cat "${publication_receipt}"
