#!/usr/bin/env bash
# Publish a previously verified manual release without rebuilding it.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: publish-manual-release.sh --release /absolute/path --manifest-sha256 sha256:HEX --output-manifest /absolute/path

Checks the transport hashes, loads all three image archives, verifies their local
IDs and OCI manifest digests against release-manifest.v1.json, pushes the exact
manifest references, verifies all registry digests, then promotes the existing
manifest by changing only its three registry_verified values to true.
EOF
}

release_root=
manifest_sha256=
output_manifest=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      release_root=$2
      shift 2
      ;;
    --output-manifest)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      output_manifest=$2
      shift 2
      ;;
    --manifest-sha256)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      manifest_sha256=$2
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ $release_root == /* && -d $release_root && ! -L $release_root ]] || {
  echo "--release must be an absolute real directory" >&2
  exit 2
}
[[ $output_manifest == /* && ! -e $output_manifest && ! -L $output_manifest ]] || {
  echo "--output-manifest must be a new absolute path" >&2
  exit 2
}
[[ $manifest_sha256 =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "--manifest-sha256 must be the approved canonical release manifest digest" >&2
  exit 2
}
for required in docker jq python3 sha256sum; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "manual release publication needs $required" >&2
    exit 1
  }
done
docker buildx version >/dev/null
tool_root=$(cd -- "$(dirname -- "$0")" && pwd -P)
transport_verifier="$tool_root/verify-image-transport.py"
release_verifier="$tool_root/verify-manual-release.py"

manifest="$release_root/release-manifest.v1.json"
checksums="$release_root/SHA256SUMS"
control_archive="$release_root/cats-control-plane-image.tar"
credential_refresher_archive="$release_root/cats-credential-refresher-image.tar"
gateway_archive="$release_root/cats-gateway-image.tar"
for input in "$manifest" "$checksums" "$control_archive" "$credential_refresher_archive" "$gateway_archive"; do
  [[ -f $input && ! -L $input ]] || {
    echo "missing regular release input: $input" >&2
    exit 1
  }
done
(
  cd "$release_root"
  [[ $(wc -l < SHA256SUMS) -eq 3 ]] || {
    echo "SHA256SUMS must name exactly the three transport archives" >&2
    exit 1
  }
  awk '
    NR == 1 { expected = "cats-control-plane-image.tar" }
    NR == 2 { expected = "cats-credential-refresher-image.tar" }
    NR == 3 { expected = "cats-gateway-image.tar" }
    $1 !~ /^[0-9a-f]{64}$/ || $2 != expected { exit 1 }
  ' SHA256SUMS || {
    echo "SHA256SUMS must contain only the three canonical transport names" >&2
    exit 1
  }
  sha256sum --check --strict SHA256SUMS
)

candidate=$(python3 -B "$release_verifier" registry-candidate \
  --manifest "$manifest" \
  --manifest-sha256 "$manifest_sha256")
control_reference=$(jq -er '.control_plane.reference' <<<"$candidate")
control_digest=$(jq -er '.control_plane.image_digest' <<<"$candidate")
control_config=$(jq -er '.control_plane.config_digest' <<<"$candidate")
credential_refresher_reference=$(jq -er '.credential_refresher.reference' <<<"$candidate")
credential_refresher_digest=$(jq -er '.credential_refresher.image_digest' <<<"$candidate")
credential_refresher_config=$(jq -er '.credential_refresher.config_digest' <<<"$candidate")
gateway_reference=$(jq -er '.gateway.reference' <<<"$candidate")
gateway_digest=$(jq -er '.gateway.image_digest' <<<"$candidate")
gateway_config=$(jq -er '.gateway.config_digest' <<<"$candidate")

verify_archive() {
  archive=$1
  expected_reference=$2
  expected_digest=$3
  expected_config=$4
  label=$5

  python3 -B "$transport_verifier" \
    --archive "$archive" \
    --reference "$expected_reference" \
    --image-digest "$expected_digest" \
    --config-digest "$expected_config"

  docker image load --input "$archive" >/dev/null
  loaded_id=$(docker image inspect --format '{{.Id}}' "$expected_reference")
  [[ $loaded_id == "$expected_config" || $loaded_id == "$expected_digest" ]] || {
    echo "$label loaded image ID differs from both release manifest identities" >&2
    exit 1
  }
  [[ $(docker image inspect --format '{{.Architecture}}/{{.Os}}' "$expected_reference") == amd64/linux ]] || {
    echo "$label loaded image is not linux/amd64" >&2
    exit 1
  }
}

verify_archive "$control_archive" "$control_reference" "$control_digest" "$control_config" Control
verify_archive \
  "$credential_refresher_archive" \
  "$credential_refresher_reference" \
  "$credential_refresher_digest" \
  "$credential_refresher_config" \
  credential-refresher
verify_archive "$gateway_archive" "$gateway_reference" "$gateway_digest" "$gateway_config" Gateway

docker push "$control_reference"
[[ $(docker buildx imagetools inspect --raw "$control_reference" | sha256sum | awk '{print "sha256:" $1}') == "$control_digest" ]] || {
  echo "registry Control digest differs from the release manifest" >&2
  exit 1
}
docker push "$credential_refresher_reference"
[[ $(docker buildx imagetools inspect --raw "$credential_refresher_reference" | sha256sum | awk '{print "sha256:" $1}') == "$credential_refresher_digest" ]] || {
  echo "registry credential-refresher digest differs from the release manifest" >&2
  exit 1
}
docker push "$gateway_reference"
[[ $(docker buildx imagetools inspect --raw "$gateway_reference" | sha256sum | awk '{print "sha256:" $1}') == "$gateway_digest" ]] || {
  echo "registry Gateway digest differs from the release manifest" >&2
  exit 1
}

python3 -B "$release_verifier" registry-candidate \
  --manifest "$manifest" \
  --manifest-sha256 "$manifest_sha256" \
  --control-registry-digest "$control_digest" \
  --credential-refresher-registry-digest "$credential_refresher_digest" \
  --gateway-registry-digest "$gateway_digest" \
  --output "$output_manifest"

echo "registry-verified manual release manifest: $output_manifest"
