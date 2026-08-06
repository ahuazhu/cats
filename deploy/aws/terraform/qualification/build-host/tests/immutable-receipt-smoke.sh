#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../bootstrap/immutable-receipt.sh
source "${script_dir}/../bootstrap/immutable-receipt.sh"

readonly smoke_dir="$(mktemp -d)"
trap 'rm -rf -- "${smoke_dir}"' EXIT
readonly target="${smoke_dir}/receipt.json"

printf '%s\n' '{"source_sha":"same"}' > "${smoke_dir}/first"
write_immutable_receipt "${smoke_dir}/first" "${target}"
cmp -s -- "${target}" <(printf '%s\n' '{"source_sha":"same"}')

printf '%s\n' '{"source_sha":"same"}' > "${smoke_dir}/same"
write_immutable_receipt "${smoke_dir}/same" "${target}"
cmp -s -- "${target}" <(printf '%s\n' '{"source_sha":"same"}')

printf '%s\n' '{"source_sha":"different"}' > "${smoke_dir}/different"
if write_immutable_receipt "${smoke_dir}/different" "${target}"; then
  echo "different immutable receipt was unexpectedly accepted" >&2
  exit 1
fi
cmp -s -- "${target}" <(printf '%s\n' '{"source_sha":"same"}')
test ! -e "${smoke_dir}/different"

if stat --format='%a' "${target}" >/dev/null 2>&1; then
  test "$(stat --format='%a' "${target}")" = "444"
else
  test "$(stat -f '%Lp' "${target}")" = "444"
fi
