#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SKILLS=(
  rust-smell-audit
  safe-refactor
  rust-pr-review
)

usage() {
  echo "usage: $0 {fmt|skills|check|build|clippy|test|doc|fast|full|linux}" >&2
}

run_fmt() {
  echo "==> cargo fmt"
  cargo fmt --all -- --check
}

run_skills() {
  echo "==> shared agent skills"
  for skill in "${SKILLS[@]}"; do
    canonical="agent-skills/$skill"
    [[ -f "$canonical/SKILL.md" ]] || {
      echo "missing $canonical/SKILL.md" >&2
      return 1
    }
    [[ -f "$canonical/agents/openai.yaml" ]] || {
      echo "missing $canonical/agents/openai.yaml" >&2
      return 1
    }
    grep -Fxq "name: $skill" "$canonical/SKILL.md" || {
      echo "$canonical/SKILL.md has the wrong name" >&2
      return 1
    }
    grep -Eq '^description: .+' "$canonical/SKILL.md" || {
      echo "$canonical/SKILL.md needs a description" >&2
      return 1
    }
    ! grep -Fq 'TODO' "$canonical/SKILL.md" || {
      echo "$canonical/SKILL.md still contains TODO text" >&2
      return 1
    }
    grep -Fq "\$$skill" "$canonical/agents/openai.yaml" || {
      echo "$canonical/agents/openai.yaml must mention \$$skill" >&2
      return 1
    }

    for surface in .agents .claude; do
      link="$surface/skills/$skill"
      [[ -L "$link" ]] || {
        echo "$link must be a symlink" >&2
        return 1
      }
      [[ "$(readlink "$link")" == "../../$canonical" ]] || {
        echo "$link points to the wrong canonical skill" >&2
        return 1
      }
      [[ -f "$link/SKILL.md" ]] || {
        echo "$link is broken" >&2
        return 1
      }
    done
  done
}

run_build() {
  echo "==> cargo build"
  cargo build --workspace --locked
}

run_check() {
  echo "==> cargo check"
  cargo check --workspace --all-targets --locked
}

run_clippy() {
  echo "==> cargo clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings
}

run_test() {
  echo "==> cargo test"
  cargo test --workspace --locked
}

run_doc() {
  echo "==> cargo doc"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
}

run_fast() {
  run_fmt
  run_skills
  run_check
  run_clippy
}

run_full() {
  run_fmt
  run_skills
  run_check
  run_build
  run_clippy
  run_test
  run_doc
}

run_linux() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for the Linux quality gate" >&2
    return 1
  }
  local platform="${CATS_LINUX_PLATFORM:-linux/arm64}"
  local target_volume="${CATS_LINUX_TARGET_VOLUME:-cats-target-linux}"
  local jobs="${CATS_LINUX_JOBS:-2}"

  docker run --rm --platform "$platform" \
    -e CARGO_BUILD_JOBS="$jobs" \
    -v "$REPO_ROOT:/work" -w /work \
    -v cats-cargo-registry:/usr/local/cargo/registry \
    -v "$target_volume:/target" \
    rust:1.97.1-bookworm \
    sh -c 'rustup component add clippy rustfmt &&
           ./scripts/quality.sh skills &&
           cargo fmt --all -- --check &&
           cargo check --workspace --all-targets --locked --target-dir /target &&
           cargo build --workspace --locked --target-dir /target &&
           cargo clippy --workspace --all-targets --locked --target-dir /target -- -D warnings &&
           cargo test --workspace --locked --target-dir /target &&
           RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --target-dir /target'
}

case "${1:-full}" in
  fmt) run_fmt ;;
  skills) run_skills ;;
  check) run_check ;;
  build) run_build ;;
  clippy) run_clippy ;;
  test) run_test ;;
  doc) run_doc ;;
  fast) run_fast ;;
  full) run_full ;;
  linux) run_linux ;;
  *)
    usage
    exit 2
    ;;
esac
