#!/usr/bin/env bash
# Build and verify one exact, non-deploying production release.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-manual-release.sh --source-sha SHA --output /absolute/path [--image REPOSITORY:TAG] [--push]

Builds the shared Guest runtime once, then the linux/amd64 Control image and
worker bundle from that same payload. The default image stays in the local
buildx cache; --push requires an immutable repository:tag reference and verifies
the reported digest against the registry before writing release-manifest.v1.json.
EOF
}

source_sha=
output_root=
image_reference=
push_image=false

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
    --push)
      push_image=true
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
if [[ $push_image == true ]]; then
  [[ -n $image_reference && $image_reference != *@* && $image_reference == */*:* ]] || {
    echo "--push requires --image with an explicit repository:tag (not a digest)" >&2
    exit 2
  }
elif [[ -z $image_reference ]]; then
  image_reference="cats-control-plane:manual-${source_sha:0:12}"
fi
[[ $image_reference != *@* && $image_reference != *[[:space:]]* ]] || {
  echo "--image must be a whitespace-free tag reference without @" >&2
  exit 2
}

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
root_touched_stage=false
output_incomplete=
cleanup() {
  if [[ -n $control_container ]]; then
    docker rm -f "$control_container" >/dev/null 2>&1 || true
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
worker_metadata="$output_incomplete/worker-image-metadata.json"
control_root="$output_incomplete/control-root"
worker_root="$output_incomplete/worker-root"
worker_bundle="$output_incomplete/cats-worker.tar.zst"
mkdir -m 0700 "$control_root" "$worker_root"

build_arguments=(
  --file deploy/aws/Dockerfile.control-plane
  --target runtime
  --platform linux/amd64
  --provenance=false
  --metadata-file "$control_metadata"
  --tag "$image_reference"
  --load
)
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
control_image_id=$(docker image inspect --format '{{.Id}}' "$image_reference")
[[ $control_image_id == "$control_config_digest" ]] || {
  echo "loaded Control image ID differs from the build config digest" >&2
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
  --worker-bundle "$worker_bundle"
  --control-image-reference "$image_reference"
  --control-image-digest "$control_image_digest"
  --control-image-config-digest "$control_config_digest"
  --source-commit "$source_sha"
  --source-tree "$source_tree"
  --source-fingerprint "$source_fingerprint"
  --input-file "cargo_lock=$source_root/Cargo.lock"
  --input-file "rust_toolchain=$source_root/rust-toolchain.toml"
  --input-file "control_dockerfile=$source_root/deploy/aws/Dockerfile.control-plane"
  --input-file "worker_dockerfile=$source_root/deploy/aws/Dockerfile.worker-artifact"
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
)
preflight_manifest="$output_incomplete/release-manifest.preflight.v1.json"
python3 deploy/aws/tools/verify-manual-release.py \
  "${verifier_arguments[@]}" \
  --control-image-registry-verified false \
  --output "$preflight_manifest"

if [[ $push_image == true ]]; then
  docker push "$image_reference"
  registry_digest=$(docker buildx imagetools inspect --raw "$image_reference" | sha256sum | awk '{print "sha256:" $1}')
  [[ $registry_digest == "$control_image_digest" ]] || {
    echo "registry Control digest differs from the verified local digest" >&2
    exit 1
  }
  python3 deploy/aws/tools/verify-manual-release.py \
    "${verifier_arguments[@]}" \
    --control-image-registry-verified true \
    --output "$output_incomplete/release-manifest.v1.json"
  rm -f -- "$preflight_manifest"
else
  mv "$preflight_manifest" "$output_incomplete/release-manifest.v1.json"
fi

# The final handoff deliberately contains only immutable deployment inputs and
# their canonical manifest, not mutable build caches or extraction scratch.
rm -rf -- "$control_root" "$worker_root" "$guest_output"
rm -f -- "$control_metadata" "$worker_metadata"
cp -R "$guest_release" "$output_incomplete/guest-runtime-release.v1"
chmod -R a-w "$output_incomplete/guest-runtime-release.v1"
chmod a-w "$output_incomplete/cats-worker.tar.zst" "$output_incomplete/release-manifest.v1.json"
mv "$output_incomplete" "$output_root"
echo "manual release ready: $output_root"
