#!/usr/bin/env bash
# Build and verify one exact, non-deploying production release.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-manual-release.sh --source-sha SHA --output /absolute/path [--image REPOSITORY:TAG] [--gateway-image REPOSITORY:TAG] [--push | --export-images]

Builds the shared Guest runtime once, then the linux/amd64 Control image,
Route v2 Gateway image and worker bundle. Default images stay local; --push
requires both explicit repository:tag references and verifies both reported
digests against the registry before writing release-manifest.v1.json.
--export-images instead writes two transport-only Docker image archives and a
SHA256SUMS file. It does not contact a registry or change manifest authority.
EOF
}

source_sha=
output_root=
image_reference=
gateway_image_reference=
push_image=false
export_images=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-sha)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      source_sha=$2
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      output_root=$2
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      image_reference=$2
      shift 2
      ;;
    --gateway-image)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      gateway_image_reference=$2
      shift 2
      ;;
    --push)
      push_image=true
      shift
      ;;
    --export-images)
      export_images=true
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ $source_sha =~ ^[0-9a-f]{40}$ ]] || {
  echo "--source-sha must be one exact 40-hex commit" >&2
  exit 2
}
[[ $output_root == /* && $output_root != *$'\n'* ]] || {
  echo "--output must be a newline-free absolute path" >&2
  exit 2
}
[[ ! -e $output_root && ! -L $output_root ]] || {
  echo "release output already exists: $output_root" >&2
  exit 1
}
[[ $push_image != true || $export_images != true ]] || {
  echo "--push and --export-images are mutually exclusive" >&2
  exit 2
}
if [[ $push_image == true || $export_images == true ]]; then
  [[ -n $image_reference && $image_reference != *@* && $image_reference == */*:* ]] || {
    echo "--push/--export-images requires --image with an explicit repository:tag (not a digest)" >&2
    exit 2
  }
  [[ -n $gateway_image_reference && $gateway_image_reference != *@* && $gateway_image_reference == */*:* ]] || {
    echo "--push/--export-images requires --gateway-image with an explicit repository:tag (not a digest)" >&2
    exit 2
  }
elif [[ -z $image_reference ]]; then
  image_reference="cats-control-plane:manual-${source_sha:0:12}"
fi
if [[ -z $gateway_image_reference ]]; then
  gateway_image_reference="cats-gateway:manual-${source_sha:0:12}"
fi
[[ $image_reference != *@* && $image_reference != *[[:space:]]* ]] || {
  echo "--image must be a whitespace-free tag reference without @" >&2
  exit 2
}
[[ $gateway_image_reference != *@* && $gateway_image_reference != *[[:space:]]* ]] || {
  echo "--gateway-image must be a whitespace-free tag reference without @" >&2
  exit 2
}

# Reject one mutable tag expressed twice (including Docker Hub and default-443
# aliases) before probing Docker or touching a network/build output.
python3 "$(dirname "$0")/manual_image_reference.py" \
  "$image_reference" "$gateway_image_reference"

for required in docker git python3 sha256sum stat tar zstd; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "manual release build needs $required" >&2
    exit 1
  }
done
docker buildx version >/dev/null
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo "manual release builds require a native x86_64 Linux host" >&2
  exit 1
}
for required in busybox cpio debootstrap mkfs.ext4 modprobe rustup sudo; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "Guest release build needs $required on the native build host" >&2
    exit 1
  }
done

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
[[ $(git rev-parse HEAD) == "$source_sha" ]] || {
  echo "checkout HEAD is not --source-sha" >&2
  exit 1
}
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || {
  echo "manual release builds require a clean checkout" >&2
  exit 1
}
[[ $(git rev-parse "${source_sha}^{commit}") == "$source_sha" ]] || {
  echo "--source-sha is not the checked-out commit" >&2
  exit 1
}
source_tree=$(git rev-parse "${source_sha}^{tree}")
source_fingerprint=$(
  printf 'cats.release.source.v1\0%s\0%s' "$source_sha" "$source_tree" \
    | sha256sum | awk '{print "sha256:" $1}'
)

umask 077
stage_parent=$(mktemp -d "${TMPDIR:-/tmp}/cats-manual-release.XXXXXX")
control_container=
gateway_container=
root_touched_stage=false
output_incomplete=
cleanup() {
  if [[ -n $control_container ]]; then
    docker rm -f "$control_container" >/dev/null 2>&1 || true
  fi
  if [[ -n $gateway_container ]]; then
    docker rm -f "$gateway_container" >/dev/null 2>&1 || true
  fi
  if [[ $root_touched_stage == true ]]; then
    sudo -n chown -Rh "$(id -u):$(id -g)" "$stage_parent" 2>/dev/null || true
  fi
  if [[ -n $output_incomplete ]]; then
    rm -rf -- "$output_incomplete"
  fi
  rm -rf -- "$stage_parent"
}
trap cleanup EXIT

source_root="$stage_parent/source"
mkdir -m 0700 "$source_root"
git archive --format=tar "$source_sha" | tar -xpf - -C "$source_root"

# Prove the exported build context is the exact Git tree, independently of the
# invoking checkout's worktree metadata and ignored files.
stage_tree=$(
  git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    --git-dir="$stage_parent/tree.git" init --quiet
  git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    --git-dir="$stage_parent/tree.git" --work-tree="$source_root" add -A
  git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    --git-dir="$stage_parent/tree.git" write-tree
)
[[ $stage_tree == "$source_tree" ]] || {
  echo "exported build context tree differs from the requested source tree" >&2
  exit 1
}

output_parent=$(dirname "$output_root")
[[ -d $output_parent && ! -L $output_parent ]] || {
  echo "release output parent must be an existing real directory: $output_parent" >&2
  exit 1
}
output_incomplete="$output_parent/.$(basename "$output_root").incomplete.$$"
[[ ! -e $output_incomplete && ! -L $output_incomplete ]] || {
  echo "private incomplete output already exists: $output_incomplete" >&2
  exit 1
}
install -d -m 0700 "$output_incomplete"

guest_output="$output_incomplete/guest-build"
guest_release="$source_root/guest-runtime-release.v1"
mkdir -m 0700 "$guest_output"
(
  cd "$source_root"
  rustup target add x86_64-unknown-linux-musl
  cargo build --locked --release -p cats-guest-agent --target x86_64-unknown-linux-musl
)
guest_agent_bin="$source_root/target/x86_64-unknown-linux-musl/release/cats-guest-agent"
guest_kernel="/boot/vmlinuz-$(uname -r)"
[[ -f $guest_kernel && ! -L $guest_kernel ]] || {
  echo "native build Host kernel is unavailable: $guest_kernel" >&2
  exit 1
}
root_touched_stage=true
sudo env \
  HOME=/root \
  GUEST_AGENT_BIN="$guest_agent_bin" \
  OUT="$guest_output" \
  RELEASE_OUT="$guest_release" \
  "$source_root/deploy/metal/build-guest-image.sh"
sudo chown -R "$(id -u):$(id -g)" "$guest_output" "$guest_release"

control_metadata="$output_incomplete/control-image-metadata.json"
gateway_metadata="$output_incomplete/gateway-image-metadata.json"
worker_metadata="$output_incomplete/worker-image-metadata.json"
control_archive="$output_incomplete/cats-control-plane-image.tar"
gateway_archive="$output_incomplete/cats-gateway-image.tar"
control_root="$output_incomplete/control-root"
gateway_root="$output_incomplete/gateway-root"
worker_root="$output_incomplete/worker-root"
worker_bundle="$output_incomplete/cats-worker.tar.zst"
mkdir -m 0700 "$control_root" "$gateway_root" "$worker_root"

build_arguments=(
  --file deploy/aws/Dockerfile.control-plane
  --target runtime
  --platform linux/amd64
  --build-arg "CATS_RELEASE_COMMIT_SHA=$source_sha"
  --provenance=false
  --metadata-file "$control_metadata"
  --tag "$image_reference"
)
if [[ $export_images == true ]]; then
  build_arguments+=(--output "type=oci,dest=$control_archive")
else
  build_arguments+=(--load)
fi
docker buildx build "${build_arguments[@]}" "$source_root"

control_image_digest=$(
  python3 - "$control_metadata" <<'PY'
import json, re, sys
with open(sys.argv[1], "rb") as source:
    metadata = json.load(source)
digest = metadata.get("containerimage.digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("buildx metadata lacks a canonical image digest")
print(digest)
PY
)
control_config_digest=$(
  python3 - "$control_metadata" <<'PY'
import json, re, sys
with open(sys.argv[1], "rb") as source:
    metadata = json.load(source)
digest = metadata.get("containerimage.config.digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("buildx metadata lacks a canonical image config digest")
print(digest)
PY
)
if [[ $export_images == true ]]; then
  PYTHONDONTWRITEBYTECODE=1 python3 deploy/aws/tools/verify-image-transport.py \
    --archive "$control_archive" \
    --reference "$image_reference" \
    --image-digest "$control_image_digest" \
    --config-digest "$control_config_digest"
  docker image load --input "$control_archive" >/dev/null
fi
control_image_id=$(docker image inspect --format '{{.Id}}' "$image_reference")
[[ $control_image_id == "$control_config_digest" || $control_image_id == "$control_image_digest" ]] || {
  echo "loaded Control image ID differs from both verified image identities" >&2
  exit 1
}
[[ $(docker image inspect --format '{{.Architecture}}/{{.Os}}' "$control_image_id") == amd64/linux ]] || {
  echo "loaded Control image is not linux/amd64" >&2
  exit 1
}

# Extract from the final OCI image by its immutable digest, not from the shared
# build input. This makes the byte-for-byte Control comparison independent.
install -d -m 0700 "$control_root/opt/cats/release"
control_container=$(docker create --platform linux/amd64 "$control_image_id")
docker cp \
  "$control_container:/opt/cats/release/guest-runtime-profile.v1.json" \
  "$control_root/opt/cats/release/guest-runtime-profile.v1.json"
docker cp \
  "$control_container:/opt/cats/release/guest-runtime-release-manifest.v1.json" \
  "$control_root/opt/cats/release/guest-runtime-release-manifest.v1.json"
docker rm "$control_container" >/dev/null
control_container=

gateway_build_arguments=(
  --file deploy/aws/Dockerfile.gateway
  --target runtime
  --platform linux/amd64
  --provenance=false
  --metadata-file "$gateway_metadata"
  --tag "$gateway_image_reference"
)
if [[ $export_images == true ]]; then
  gateway_build_arguments+=(--output "type=oci,dest=$gateway_archive")
else
  gateway_build_arguments+=(--load)
fi
docker buildx build "${gateway_build_arguments[@]}" "$source_root"

gateway_image_digest=$(
  python3 - "$gateway_metadata" <<'PY'
import json, re, sys
with open(sys.argv[1], "rb") as source:
    metadata = json.load(source)
digest = metadata.get("containerimage.digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("Gateway buildx metadata lacks a canonical image digest")
print(digest)
PY
)
gateway_config_digest=$(
  python3 - "$gateway_metadata" <<'PY'
import json, re, sys
with open(sys.argv[1], "rb") as source:
    metadata = json.load(source)
digest = metadata.get("containerimage.config.digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("Gateway buildx metadata lacks a canonical image config digest")
print(digest)
PY
)
if [[ $export_images == true ]]; then
  PYTHONDONTWRITEBYTECODE=1 python3 deploy/aws/tools/verify-image-transport.py \
    --archive "$gateway_archive" \
    --reference "$gateway_image_reference" \
    --image-digest "$gateway_image_digest" \
    --config-digest "$gateway_config_digest"
  docker image load --input "$gateway_archive" >/dev/null
fi
gateway_image_id=$(docker image inspect --format '{{.Id}}' "$gateway_image_reference")
[[ $gateway_image_id == "$gateway_config_digest" || $gateway_image_id == "$gateway_image_digest" ]] || {
  echo "loaded Gateway image ID differs from both verified image identities" >&2
  exit 1
}
[[ $(docker image inspect --format '{{.Architecture}}/{{.Os}}' "$gateway_image_id") == amd64/linux ]] || {
  echo "loaded Gateway image is not linux/amd64" >&2
  exit 1
}

install -d -m 0700 "$gateway_root/usr/local/bin"
gateway_container=$(docker create --platform linux/amd64 "$gateway_image_id")
docker cp \
  "$gateway_container:/usr/local/bin/cats-gatewayd" \
  "$gateway_root/usr/local/bin/cats-gatewayd"
docker rm "$gateway_container" >/dev/null
gateway_container=
chmod 0755 "$gateway_root/usr/local/bin/cats-gatewayd"

docker buildx build \
  --file deploy/aws/Dockerfile.worker-artifact \
  --target artifact \
  --platform linux/amd64 \
  --provenance=false \
  --metadata-file "$worker_metadata" \
  --output "type=local,dest=$worker_root" \
  "$source_root"

tar --owner=0 --group=0 --numeric-owner --sort=name \
  --mtime='UTC 1970-01-01' -C "$worker_root" -cf - . \
  | zstd -19 -T0 -o "$worker_bundle"
tar --zstd -tvf "$worker_bundle" \
  | awk '$NF == "./install-guest-runtime-release.sh" && substr($1,1,4) == "-rwx" { found=1 } END { exit !found }'

verifier_arguments=(
  --shared-guest-runtime "$guest_release"
  --control-root "$control_root"
  --gateway-image-root "$gateway_root"
  --worker-bundle "$worker_bundle"
  --control-image-reference "$image_reference"
  --control-image-digest "$control_image_digest"
  --control-image-config-digest "$control_config_digest"
  --gateway-image-reference "$gateway_image_reference"
  --gateway-image-digest "$gateway_image_digest"
  --gateway-image-config-digest "$gateway_config_digest"
  --source-commit "$source_sha"
  --source-tree "$source_tree"
  --source-fingerprint "$source_fingerprint"
  --input-file "cargo_lock=$source_root/Cargo.lock"
  --input-file "rust_toolchain=$source_root/rust-toolchain.toml"
  --input-file "control_dockerfile=$source_root/deploy/aws/Dockerfile.control-plane"
  --input-file "gateway_dockerfile=$source_root/deploy/aws/Dockerfile.gateway"
  --input-file "worker_dockerfile=$source_root/deploy/aws/Dockerfile.worker-artifact"
  --input-file "old_host_positive_stop=$source_root/deploy/aws/old-host-positive-stop.py"
  --input-file "qualification_catalog=$source_root/deploy/metal/runtime-cutover-e2e-catalog.v1.json"
  --input-file "guest_builder=$source_root/deploy/metal/build-guest-image.sh"
  --input-file "guest_host_kernel=$guest_kernel"
  --input-file "guest_host_modules=/lib/modules/$(uname -r)/modules.dep"
  --input-file "guest_build_sums=$guest_output/SHA256SUMS"
  --input-file "guest_rootfs_manifest=$guest_output/rootfs.manifest"
  --input-file "guest_agent_binary=$guest_agent_bin"
  --input-file "control_build_metadata=$control_metadata"
  --input-file "worker_build_metadata=$worker_metadata"
  --input-file "release_verifier=$source_root/deploy/aws/tools/verify-manual-release.py"
  --input-file "release_builder=$source_root/deploy/aws/tools/build-manual-release.sh"
  --input-file "manual_image_reference_validator=$source_root/deploy/aws/tools/manual_image_reference.py"
  --input-file "image_transport_verifier=$source_root/deploy/aws/tools/verify-image-transport.py"
)
preflight_manifest="$output_incomplete/release-manifest.preflight.v1.json"
PYTHONDONTWRITEBYTECODE=1 python3 deploy/aws/tools/verify-manual-release.py \
  "${verifier_arguments[@]}" \
  --control-image-registry-verified false \
  --gateway-image-registry-verified false \
  --output "$preflight_manifest"

if [[ $push_image == true ]]; then
  docker push "$image_reference"
  control_registry_digest=$(docker buildx imagetools inspect --raw "$image_reference" | sha256sum | awk '{print "sha256:" $1}')
  [[ $control_registry_digest == "$control_image_digest" ]] || {
    echo "registry Control digest differs from the verified local digest" >&2
    exit 1
  }
  docker push "$gateway_image_reference"
  gateway_registry_digest=$(docker buildx imagetools inspect --raw "$gateway_image_reference" | sha256sum | awk '{print "sha256:" $1}')
  [[ $gateway_registry_digest == "$gateway_image_digest" ]] || {
    echo "registry Gateway digest differs from the verified local digest" >&2
    exit 1
  }
  PYTHONDONTWRITEBYTECODE=1 python3 deploy/aws/tools/verify-manual-release.py \
    "${verifier_arguments[@]}" \
    --control-image-registry-verified true \
    --gateway-image-registry-verified true \
    --output "$output_incomplete/release-manifest.v1.json"
  rm -f -- "$preflight_manifest"
else
  mv "$preflight_manifest" "$output_incomplete/release-manifest.v1.json"
fi

if [[ $export_images == true ]]; then
  (
    cd "$output_incomplete"
    sha256sum \
      cats-control-plane-image.tar \
      cats-gateway-image.tar \
      > SHA256SUMS
  )
fi

# The final handoff deliberately contains only immutable deployment inputs and
# their canonical manifest, not mutable build caches or extraction scratch.
rm -rf -- "$control_root" "$gateway_root" "$worker_root" "$guest_output"
rm -f -- "$control_metadata" "$gateway_metadata" "$worker_metadata"
cp -R "$guest_release" "$output_incomplete/guest-runtime-release.v1"
chmod -R a-w "$output_incomplete/guest-runtime-release.v1"
chmod a-w "$output_incomplete/cats-worker.tar.zst" "$output_incomplete/release-manifest.v1.json"
if [[ $export_images == true ]]; then
  chmod a-w \
    "$output_incomplete/cats-control-plane-image.tar" \
    "$output_incomplete/cats-gateway-image.tar" \
    "$output_incomplete/SHA256SUMS"
fi
mv "$output_incomplete" "$output_root"
echo "manual release ready: $output_root"
