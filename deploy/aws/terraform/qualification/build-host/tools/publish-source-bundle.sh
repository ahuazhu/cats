#!/usr/bin/env bash
set -euo pipefail

readonly receipt_library="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../bootstrap" && pwd)/immutable-receipt.sh"
# shellcheck source=/dev/null
source "${receipt_library}"

if [[ $# -ne 7 || ! $3 =~ ^[0-9a-f]{40}$ || ! $1 =~ ^[0-9]{12}$ ]]; then
  echo "usage: publish-source-bundle <expected-account-id> <clean-repository> <40hex-commit> <source-bucket> <source-kms-alias-arn> <work-directory> <evidence-json>" >&2
  exit 64
fi
readonly expected_account_id="$1"
readonly repository_input="$2"
readonly source_sha="$3"
readonly source_bucket="$4"
readonly source_kms_alias_arn="$5"
readonly work_parent="$6"
readonly evidence_path="$7"

if [[ "${source_bucket}" != "cats-qualification-v2-build-source-${expected_account_id}-us-east-1" ]]; then
  echo "source bucket is outside the qualification boundary" >&2
  exit 65
fi
if [[ "${source_kms_alias_arn}" != "arn:aws:kms:us-east-1:${expected_account_id}:alias/cats-qualification-v2-build-source" ]]; then
  echo "source KMS alias is outside the qualification boundary" >&2
  exit 65
fi
readonly repository="$(cd -- "${repository_input}" && pwd -P)"
readonly evidence_dir="$(dirname -- "${evidence_path}")"
for directory in "${work_parent}" "${evidence_dir}"; do
  if [[ ! -d "${directory}" || -L "${directory}" || ! -w "${directory}" ]]; then
    echo "work and evidence directories must pre-exist, be non-symlink directories, and be writable" >&2
    exit 65
  fi
done
if [[ "$(aws sts get-caller-identity --query Account --output text --no-cli-pager)" != "${expected_account_id}" ]]; then
  echo "AWS caller is outside the production qualification account" >&2
  exit 65
fi
readonly source_kms_key_arn="$(
  aws kms describe-key \
    --key-id "${source_kms_alias_arn}" \
    --query KeyMetadata.Arn \
    --output text \
    --no-cli-pager
)"
if [[ ! "${source_kms_key_arn}" =~ ^arn:aws:kms:us-east-1:${expected_account_id}:key/[0-9a-f-]{36}$ ]]; then
  echo "source KMS alias resolved outside the qualification boundary" >&2
  exit 65
fi
readonly work_dir="$(mktemp -d "${work_parent}/source-bundle.XXXXXX")"
prepared_evidence=""
cleanup() {
  rm -rf -- "${work_dir}"
  [[ -z "${prepared_evidence}" || ! -e "${prepared_evidence}" ]] || rm -f -- "${prepared_evidence}"
}
trap cleanup EXIT HUP INT TERM
readonly git_home="${work_dir}/git-home"
readonly bare_repo="${work_dir}/source.git"
readonly bundle_file="${work_dir}/source.bundle"
readonly manifest_file="${work_dir}/manifest.json"
mkdir -m 0700 "${git_home}"

git_safe() {
  env -i \
    PATH=/usr/local/bin:/usr/bin:/bin \
    HOME="${git_home}" \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

if [[ "$(git_safe -C "${repository}" rev-parse HEAD)" != "${source_sha}" ]]; then
  echo "repository HEAD is not the requested exact commit" >&2
  exit 66
fi
if [[ -n "$(git_safe -C "${repository}" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "controller repository must be clean" >&2
  exit 66
fi
readonly remote_url="$(git_safe -C "${repository}" remote get-url origin)"
case "${remote_url}" in
  https://github.com/ahuazhu/cats.git|git@github.com:ahuazhu/cats.git|ssh://git@github.com/ahuazhu/cats.git) ;;
  *) echo "controller repository origin is not ahuazhu/cats" >&2; exit 66 ;;
esac
if git_safe -C "${repository}" cat-file -e HEAD:.gitmodules 2>/dev/null; then
  echo "source with submodules is not accepted" >&2
  exit 67
fi
if git_safe -C "${repository}" ls-tree -r HEAD | awk '$1 == "160000" { found = 1 } END { exit found ? 0 : 1 }'; then
  echo "source with gitlinks is not accepted" >&2
  exit 67
fi
if git_safe -C "${repository}" grep -I -l '^version https://git-lfs.github.com/spec/v1$' HEAD -- >/dev/null 2>&1; then
  echo "source with Git LFS pointers is not accepted" >&2
  exit 67
fi
readonly tree_sha="$(git_safe -C "${repository}" rev-parse 'HEAD^{tree}')"

git_safe init --bare "${bare_repo}" >/dev/null
git_safe -C "${bare_repo}" fetch --quiet --no-tags "${repository}" "${source_sha}"
git_safe -C "${bare_repo}" update-ref refs/heads/exact-source FETCH_HEAD
git_safe -C "${bare_repo}" bundle create "${bundle_file}" refs/heads/exact-source
git_safe -C "${bare_repo}" bundle verify "${bundle_file}" >/dev/null
readonly bundle_heads="$(git_safe -C "${bare_repo}" bundle list-heads "${bundle_file}")"
if [[ "${bundle_heads}" != "${source_sha} refs/heads/exact-source" ]]; then
  echo "generated bundle has an unexpected ref boundary" >&2
  exit 68
fi
readonly bundle_sha256="$(sha256sum "${bundle_file}" | awk '{print $1}')"
readonly bundle_checksum_sha256="$(openssl dgst -sha256 -binary "${bundle_file}" | base64 | tr -d '\n')"
readonly bundle_size="$(wc -c <"${bundle_file}" | tr -d '[:space:]')"
if (( bundle_size <= 0 || bundle_size > 1073741824 )); then
  echo "source bundle is outside the 1 GiB delivery boundary" >&2
  exit 68
fi
readonly bundle_key="source/bundles/sha256/${bundle_sha256}.bundle"

put_content_addressed() {
  local file="$1"
  local key="$2"
  local expected_checksum="$3"
  local expected_size="$4"
  local put_response="$5"
  local head_response="$6"
  if ! aws s3api put-object \
    --bucket "${source_bucket}" \
    --expected-bucket-owner "${expected_account_id}" \
    --key "${key}" \
    --body "${file}" \
    --if-none-match '*' \
    --checksum-algorithm SHA256 \
    --server-side-encryption aws:kms \
    --ssekms-key-id "${source_kms_alias_arn}" \
    --no-cli-pager >"${put_response}"; then
    : # A prior same-digest publication is accepted only after exact HEAD proof.
  fi
  aws s3api head-object \
    --bucket "${source_bucket}" \
    --expected-bucket-owner "${expected_account_id}" \
    --key "${key}" \
    --checksum-mode ENABLED \
    --no-cli-pager >"${head_response}"
  jq -e \
    --arg checksum "${expected_checksum}" \
    --arg kms "${source_kms_key_arn}" \
    --argjson size "${expected_size}" \
    '.ChecksumSHA256 == $checksum and .ContentLength == $size and
     .ServerSideEncryption == "aws:kms" and .SSEKMSKeyId == $kms and
     (.VersionId | type == "string" and length > 0)' \
    "${head_response}" >/dev/null
}

readonly bundle_put_response="${work_dir}/bundle-put.json"
readonly bundle_head_response="${work_dir}/bundle-head.json"
put_content_addressed \
  "${bundle_file}" "${bundle_key}" "${bundle_checksum_sha256}" "${bundle_size}" \
  "${bundle_put_response}" "${bundle_head_response}"
readonly bundle_version_id="$(jq -er '.VersionId' "${bundle_head_response}")"

jq -n -S \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  --arg bundle_checksum_sha256 "${bundle_checksum_sha256}" \
  --arg bundle_key "${bundle_key}" \
  --arg bundle_version_id "${bundle_version_id}" \
  --argjson bundle_size "${bundle_size}" \
  '{schema_version: 1, repository: "https://github.com/ahuazhu/cats.git", source_sha: $source_sha, tree_sha: $tree_sha, bundle: {sha256: $bundle_sha256, size_bytes: $bundle_size, object_key: $bundle_key, version_id: $bundle_version_id, checksum_sha256: $bundle_checksum_sha256}, policies: {submodules: "rejected", gitlinks: "rejected", git_lfs: "rejected"}}' \
  >"${manifest_file}"
readonly manifest_sha256="$(sha256sum "${manifest_file}" | awk '{print $1}')"
readonly manifest_checksum_sha256="$(openssl dgst -sha256 -binary "${manifest_file}" | base64 | tr -d '\n')"
readonly manifest_size="$(wc -c <"${manifest_file}" | tr -d '[:space:]')"
readonly manifest_key="source/manifests/sha256/${manifest_sha256}.json"
readonly manifest_put_response="${work_dir}/manifest-put.json"
readonly manifest_head_response="${work_dir}/manifest-head.json"
put_content_addressed \
  "${manifest_file}" "${manifest_key}" "${manifest_checksum_sha256}" "${manifest_size}" \
  "${manifest_put_response}" "${manifest_head_response}"

prepared_evidence="$(mktemp "${evidence_dir}/.source-bundle-evidence.XXXXXX")"
jq -n -S \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  --arg manifest_key "${manifest_key}" \
  --arg bundle_key "${bundle_key}" \
  --arg manifest_version_id "$(jq -er '.VersionId' "${manifest_head_response}")" \
  --arg bundle_version_id "${bundle_version_id}" \
  '{schema_version: 1, status: "published", source_sha: $source_sha, tree_sha: $tree_sha, manifest_sha256: $manifest_sha256, bundle_sha256: $bundle_sha256, manifest_object_key: $manifest_key, bundle_object_key: $bundle_key, manifest_version_id: $manifest_version_id, bundle_version_id: $bundle_version_id, conditional_create: true, github_credential_on_build_host: false}' \
  >"${prepared_evidence}"
write_immutable_receipt "${prepared_evidence}" "${evidence_path}"
jq -n -S \
  --arg source_sha "${source_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  --arg evidence_path "${evidence_path}" \
  '{source_sha: $source_sha, manifest_sha256: $manifest_sha256, bundle_sha256: $bundle_sha256, evidence_path: $evidence_path}'
