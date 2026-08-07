#!/usr/bin/env bash
set -euo pipefail

readonly identity_file="/etc/cats-build/identity.json"
readonly receipt_library="/usr/local/lib/cats-build/immutable-receipt.sh"
readonly source_parent="/srv/cats-build"
readonly source_dir="${source_parent}/source"
readonly target_parent="${source_parent}/target"
readonly receipt_dir="/var/lib/cats-build/source-receipts"
readonly lock_file="/run/lock/cats-source-delivery.lock"

# shellcheck source=/dev/null
source "${receipt_library}"

if [[ "$(id -u)" != "0" ]]; then
  echo "cats-checkout-exact-sha must run as root" >&2
  exit 77
fi
if [[ $# -ne 3 || ! $1 =~ ^[0-9a-f]{40}$ || ! $2 =~ ^[0-9a-f]{64}$ || ! $3 =~ ^[0-9a-f]{64}$ ]]; then
  echo "usage: cats-checkout-exact-sha <40hex-commit> <64hex-manifest-sha256> <64hex-bundle-sha256>" >&2
  exit 64
fi
readonly source_sha="$1"
readonly manifest_sha256="$2"
readonly bundle_sha256="$3"
readonly source_bucket="$(jq -er '.source_bucket' "${identity_file}")"
readonly source_kms_alias_arn="$(jq -er '.source_kms_alias_arn' "${identity_file}")"
readonly source_kms_key_arn="$(
  aws kms describe-key \
    --key-id "${source_kms_alias_arn}" \
    --query KeyMetadata.Arn \
    --output text \
    --no-cli-pager
)"
readonly manifest_key="source/manifests/sha256/${manifest_sha256}.json"
readonly bundle_key="source/bundles/sha256/${bundle_sha256}.bundle"

install -d -m 0755 -o root -g root "${source_parent}" "${receipt_dir}" /run/lock
install -d -m 0755 -o root -g root "${target_parent}"
exec 9>"${lock_file}"
flock -x 9

readonly work_dir="$(mktemp -d "${source_parent}/.source-delivery.XXXXXX")"
readonly stage_repo="${work_dir}/repo"
readonly manifest_file="${work_dir}/manifest.json"
readonly bundle_file="${work_dir}/source.bundle"
readonly manifest_response="${work_dir}/manifest-response.json"
readonly bundle_response="${work_dir}/bundle-response.json"
readonly git_home="${work_dir}/git-home"
prepared_receipt=""
cleanup() {
  rm -rf -- "${work_dir}"
  [[ -z "${prepared_receipt}" || ! -e "${prepared_receipt}" ]] || rm -f -- "${prepared_receipt}"
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "${work_dir}"
mkdir -m 0700 "${git_home}"

aws s3api get-object \
  --bucket "${source_bucket}" \
  --expected-bucket-owner "$(jq -er '.account_id' "${identity_file}")" \
  --key "${manifest_key}" \
  --checksum-mode ENABLED \
  --no-cli-pager \
  "${manifest_file}" >"${manifest_response}"
if [[ "$(sha256sum "${manifest_file}" | awk '{print $1}')" != "${manifest_sha256}" ]]; then
  echo "source manifest digest mismatch" >&2
  exit 65
fi
jq -e \
  --arg source_sha "${source_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  --arg bundle_key "${bundle_key}" \
  'keys == ["bundle", "policies", "repository", "schema_version", "source_sha", "tree_sha"] and
   .schema_version == 1 and
   .repository == "https://github.com/ahuazhu/cats.git" and
   .source_sha == $source_sha and (.tree_sha | test("^[0-9a-f]{40}$")) and
   (.bundle | keys == ["checksum_sha256", "object_key", "sha256", "size_bytes", "version_id"]) and
   .bundle.object_key == $bundle_key and .bundle.sha256 == $bundle_sha256 and
   (.bundle.checksum_sha256 | test("^[A-Za-z0-9+/]{43}=$")) and
   (.bundle.version_id | type == "string" and length > 0) and
   (.bundle.size_bytes | type == "number" and . > 0 and . <= 1073741824) and
   .policies == {git_lfs: "rejected", gitlinks: "rejected", submodules: "rejected"}' \
  "${manifest_file}" >/dev/null
jq -e \
  --arg kms "${source_kms_key_arn}" \
  '.ServerSideEncryption == "aws:kms" and .SSEKMSKeyId == $kms and
   (.VersionId | type == "string" and length > 0) and
   (.ChecksumSHA256 | type == "string" and length > 0)' \
  "${manifest_response}" >/dev/null

aws s3api get-object \
  --bucket "${source_bucket}" \
  --expected-bucket-owner "$(jq -er '.account_id' "${identity_file}")" \
  --key "${bundle_key}" \
  --version-id "$(jq -er '.bundle.version_id' "${manifest_file}")" \
  --checksum-mode ENABLED \
  --no-cli-pager \
  "${bundle_file}" >"${bundle_response}"
readonly observed_bundle_size="$(wc -c <"${bundle_file}" | tr -d '[:space:]')"
if [[ "${observed_bundle_size}" != "$(jq -er '.bundle.size_bytes' "${manifest_file}")" ]]; then
  echo "source bundle size mismatch" >&2
  exit 66
fi
if [[ "$(sha256sum "${bundle_file}" | awk '{print $1}')" != "${bundle_sha256}" ]]; then
  echo "source bundle digest mismatch" >&2
  exit 66
fi
jq -e \
  --arg kms "${source_kms_key_arn}" \
  --arg version_id "$(jq -er '.bundle.version_id' "${manifest_file}")" \
  --arg checksum "$(jq -er '.bundle.checksum_sha256' "${manifest_file}")" \
  '.ServerSideEncryption == "aws:kms" and .SSEKMSKeyId == $kms and
   .VersionId == $version_id and .ChecksumSHA256 == $checksum' \
  "${bundle_response}" >/dev/null

git_safe() {
  env -i \
    PATH=/usr/local/bin:/usr/bin:/bin \
    HOME="${git_home}" \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

mkdir -m 0700 "${stage_repo}"
git_safe -C "${stage_repo}" init --initial-branch=detached-source >/dev/null
git_safe -C "${stage_repo}" bundle verify "${bundle_file}" >/dev/null
readonly bundle_heads="$(git_safe -C "${stage_repo}" bundle list-heads "${bundle_file}")"
if [[ "${bundle_heads}" != "${source_sha} refs/heads/exact-source" ]]; then
  echo "source bundle does not expose exactly the requested commit" >&2
  exit 67
fi
git_safe -C "${stage_repo}" fetch --no-tags "${bundle_file}" refs/heads/exact-source >/dev/null
git_safe -C "${stage_repo}" switch --detach FETCH_HEAD >/dev/null
if [[ "$(git_safe -C "${stage_repo}" rev-parse HEAD)" != "${source_sha}" ]]; then
  echo "source bundle resolved to another commit" >&2
  exit 68
fi
readonly tree_sha="$(git_safe -C "${stage_repo}" rev-parse 'HEAD^{tree}')"
if [[ "${tree_sha}" != "$(jq -er '.tree_sha' "${manifest_file}")" ]]; then
  echo "source tree differs from the controller manifest" >&2
  exit 68
fi
if [[ -n "$(git_safe -C "${stage_repo}" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "expanded source tree is not clean" >&2
  exit 69
fi
if git_safe -C "${stage_repo}" cat-file -e HEAD:.gitmodules 2>/dev/null; then
  echo "source with submodules is not accepted" >&2
  exit 70
fi
if git_safe -C "${stage_repo}" ls-tree -r HEAD | awk '$1 == "160000" { found = 1 } END { exit found ? 0 : 1 }'; then
  echo "source with gitlinks is not accepted" >&2
  exit 70
fi
if git_safe -C "${stage_repo}" grep -I -l '^version https://git-lfs.github.com/spec/v1$' HEAD -- >/dev/null 2>&1; then
  echo "source with Git LFS pointers is not accepted" >&2
  exit 70
fi

jq -n -S \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  '{schema_version: 1, source_sha: $source_sha, tree_sha: $tree_sha, manifest_sha256: $manifest_sha256, bundle_sha256: $bundle_sha256}' \
  >"${stage_repo}/.git/cats-active-delivery-v1.json"

find -P "${stage_repo}" -xdev -type d -exec chmod 0555 {} +
while IFS= read -r -d '' path; do
  if [[ -x "${path}" ]]; then
    chmod 0555 "${path}"
  else
    chmod 0444 "${path}"
  fi
done < <(find -P "${stage_repo}" -xdev -type f -print0)
chown -R root:root "${stage_repo}"

readonly receipt_path="${receipt_dir}/${source_sha}-${manifest_sha256}.json"
prepared_receipt="$(mktemp "${receipt_dir}/.${source_sha}-${manifest_sha256}.XXXXXX")"
jq -n -S \
  --arg source_sha "${source_sha}" \
  --arg tree_sha "${tree_sha}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg bundle_sha256 "${bundle_sha256}" \
  --arg manifest_key "${manifest_key}" \
  --arg bundle_key "${bundle_key}" \
  --arg manifest_version_id "$(jq -er '.VersionId' "${manifest_response}")" \
  --arg manifest_checksum_sha256 "$(jq -er '.ChecksumSHA256' "${manifest_response}")" \
  --arg bundle_version_id "$(jq -er '.bundle.version_id' "${manifest_file}")" \
  '{schema_version: 1, source_sha: $source_sha, tree_sha: $tree_sha, manifest_sha256: $manifest_sha256, bundle_sha256: $bundle_sha256, manifest_object_key: $manifest_key, manifest_version_id: $manifest_version_id, manifest_checksum_sha256: $manifest_checksum_sha256, bundle_object_key: $bundle_key, bundle_version_id: $bundle_version_id, source_owner: "root", source_writable_by_build: false}' \
  >"${prepared_receipt}"

readonly previous_source="${source_parent}/.source-previous.$$"
if [[ -e "${previous_source}" ]]; then
  echo "source publication scratch path already exists" >&2
  exit 71
fi
if [[ -e "${source_dir}" ]]; then
  mv -- "${source_dir}" "${previous_source}"
fi
if ! mv -- "${stage_repo}" "${source_dir}"; then
  [[ ! -e "${previous_source}" ]] || mv -- "${previous_source}" "${source_dir}"
  exit 72
fi
if ! write_immutable_receipt "${prepared_receipt}" "${receipt_path}"; then
  rm -rf -- "${source_dir}"
  [[ ! -e "${previous_source}" ]] || mv -- "${previous_source}" "${source_dir}"
  exit 73
fi
chown root:root "${receipt_path}"
rm -rf -- "${previous_source}"

jq -n -S \
  --arg source_dir "${source_dir}" \
  --arg target_parent "${target_parent}" \
  --arg receipt_path "${receipt_path}" \
  '{source_dir: $source_dir, target_parent: $target_parent, receipt_path: $receipt_path}'
