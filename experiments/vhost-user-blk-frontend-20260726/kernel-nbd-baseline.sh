#!/usr/bin/env bash
# Measure the *real* Phase A host-side block chain for comparison:
#
#   fio (O_DIRECT) -> host kernel block layer -> /dev/nbdN -> kernel NBD client
#   -> unix socket -> cats-blockd NBD frontend -> ChunkEngine -> file BlobStore
#
# This is the path `--ch-block-path kernel-nbd` puts under Cloud Hypervisor,
# minus the Guest kernel and the VMM's own block backend. It needs the `nbd`
# kernel module, `nbd-client`, `fio` and a privileged container; the run.sh
# harness does not, which is why this is a separate script.
#
#   ./kernel-nbd-baseline.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
rel="${here#"$repo"/}"
image="${CATS_RUST_IMAGE:-rust:1.97-bookworm}"
runtime="${CATS_FIO_RUNTIME:-10}"

if [ "$(uname -s)" != "Linux" ]; then
  case "$(uname -m)" in
    arm64 | aarch64) platform=linux/arm64 ;;
    x86_64) platform=linux/amd64 ;;
    *)
      echo "unsupported host architecture $(uname -m)" >&2
      exit 1
      ;;
  esac
  echo "== not Linux: re-running privileged in $image ($platform)"
  exec docker run --rm --privileged --platform "$platform" \
    -v "$repo":/work -w /work \
    -v cats-cargo-registry:/usr/local/cargo/registry \
    -v cats-target-linux:/target \
    -e CATS_TARGET_DIR=/target \
    -e CATS_FIO_RUNTIME="$runtime" \
    "$image" "/work/$rel/kernel-nbd-baseline.sh"
fi

target_dir="${CATS_TARGET_DIR:-$repo/target-linux/$(uname -m)}"
raw="$here/raw"
mkdir -p "$raw"

if [ ! -e /dev/nbd0 ]; then
  echo "no /dev/nbd0: load the nbd module on the host (modprobe nbd nbds_max=8)" >&2
  exit 1
fi
for tool in nbd-client fio python3; do
  command -v "$tool" >/dev/null || {
    echo "== installing measurement tools"
    apt-get -qq update >/dev/null
    apt-get -qq install -y nbd-client fio python3 >/dev/null
    break
  }
done

echo "== building cats-blockd (release)"
cargo build --release -p cats-blockd-daemon --target-dir "$target_dir" >/dev/null
blockd="$target_dir/release/cats-blockd"

work="$(mktemp -d)"
socket="$work/nbd.sock"
device=/dev/nbd0
volume_size=$((64 * 1024 * 1024))
span=$((32 * 1024 * 1024))

cleanup() {
  nbd-client -d "$device" >/dev/null 2>&1 || true
  [ -n "${blockd_pid:-}" ] && kill "$blockd_pid" 2>/dev/null || true
  wait "${blockd_pid:-}" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

"$blockd" \
  --volume-id vol_kernel_nbd --attachment-id att-fio \
  --data-dir "$work/data" \
  --metadata-store-adapter sqlite --metadata-store-option "path=$work/meta.db" \
  --object-store-adapter file --object-store-option "root=$work/blob" \
  --listen-unix "$socket" --create-volume-size "$volume_size" \
  >"$work/ready.log" 2>"$raw/kernel-nbd-blockd.log" &
blockd_pid=$!
for _ in $(seq 1 100); do
  grep -q '^READY ' "$work/ready.log" 2>/dev/null && break
  sleep 0.1
done
grep -q '^READY ' "$work/ready.log" || {
  echo "cats-blockd never became ready" >&2
  exit 1
}

echo "== attaching $device (block size 512, as the node agent does)"
nbd-client -unix "$socket" "$device" -b 512 -N '' >"$raw/kernel-nbd-attach.log" 2>&1
sectors="$(cat /sys/block/nbd0/size)"
echo "device sectors: $sectors"

echo "== warming the addressable span so fio never measures a first-touch fetch"
dd if=/dev/zero of="$device" bs=1M count=$((span / 1024 / 1024)) oflag=direct status=none
sync

run_fio() {
  local name="$1" rw="$2" bs="$3" depth="$4"
  fio --name="$name" --filename="$device" --direct=1 --ioengine=libaio \
    --rw="$rw" --bs="$bs" --iodepth="$depth" --numjobs=1 \
    --size="$span" --time_based --runtime="$runtime" --ramp_time=2 \
    --norandommap --randrepeat=1 --group_reporting \
    --output-format=json --output="$raw/fio-$name.json" >/dev/null
  echo "  $name done"
}

echo "== fio (O_DIRECT, ${runtime}s per point)"
run_fio randread-4k-qd1 randread 4k 1
run_fio randwrite-4k-qd1 randwrite 4k 1
run_fio randread-4k-qd32 randread 4k 32
run_fio randwrite-4k-qd32 randwrite 4k 32
run_fio seqread-1m-qd1 read 1M 1
run_fio seqwrite-1m-qd1 write 1M 1

python3 - "$raw" <<'PY'
import glob, json, os, sys
raw = sys.argv[1]
rows = ["workload,rw,block_bytes,iodepth,iops,mib_per_sec,mean_us,p50_us,p99_us"]
for path in sorted(glob.glob(os.path.join(raw, "fio-*.json"))):
    with open(path) as handle:
        report = json.load(handle)
    job = report["jobs"][0]
    name = job["jobname"]
    options = job["job options"]
    side = job["write"] if options["rw"] in ("write", "randwrite") else job["read"]
    percentiles = side["clat_ns"].get("percentile", {})
    rows.append(
        "{},{},{},{},{:.0f},{:.3f},{:.1f},{:.0f},{:.0f}".format(
            name,
            options["rw"],
            side["bs_max"] if "bs_max" in side else options["bs"],
            options["iodepth"],
            side["iops"],
            side["bw_bytes"] / (1024 * 1024),
            side["clat_ns"]["mean"] / 1000.0,
            percentiles.get("50.000000", 0) / 1000.0,
            percentiles.get("99.000000", 0) / 1000.0,
        )
    )
out = os.path.join(raw, "kernel-nbd-fio.csv")
with open(out, "w") as handle:
    handle.write("\n".join(rows) + "\n")
print("\n".join(rows))
print("wrote", out)
PY

echo "== done"
