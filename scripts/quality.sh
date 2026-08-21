#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CATS_CARGO_DENY_VERSION="${CATS_CARGO_DENY_VERSION:-0.19.4}"
CATS_CARGO_MACHETE_VERSION="${CATS_CARGO_MACHETE_VERSION:-0.9.2}"

SKILLS=(
  rust-smell-audit
  safe-refactor
  rust-pr-review
  verify-the-probe
)

usage() {
  echo "usage: $0 {provenance|fmt|skills|deps|check|build|clippy|test|doc|fast|full|linux}" >&2
}

prepare_native_test_process() {
  local hard_nofile
  local native_tool

  if [[ "$(uname -s)" == Linux ]]; then
    case ":$PATH:" in
      *:/usr/sbin:*) ;;
      *) export PATH="$PATH:/usr/sbin" ;;
    esac
    for native_tool in mkfs.ext4 debugfs e2fsck; do
      command -v "$native_tool" >/dev/null 2>&1 || {
        echo "Linux native tests need e2fsprogs: $native_tool is not in PATH" >&2
        return 1
      }
    done
  fi

  hard_nofile="$(ulimit -Hn)" || return 1
  ulimit -Sn "$hard_nofile" || {
    echo "cannot raise the test process open-file limit to $hard_nofile" >&2
    return 1
  }
  echo "==> test process limits (threads=4 nofile=$(ulimit -Sn))"
}

source_git() {
  GIT_OPTIONAL_LOCKS=0 git \
    -c safe.directory="$REPO_ROOT" \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false \
    -C "$REPO_ROOT" \
    "$@"
}

source_fingerprint() {
  local head
  local tracked
  local untracked

  head="$(source_git rev-parse HEAD)" || return 1
  tracked="$(source_git diff --binary HEAD -- | source_git hash-object --stdin)" || return 1
  untracked="$({
    source_git ls-files --others --exclude-standard -z
  } | while IFS= read -r -d '' path; do
    printf 'untracked\0%s\0' "$path"
    source_git hash-object -- "$path" || exit 1
  done | source_git hash-object --stdin)" || return 1

  printf '%s\0%s\0%s\n' "$head" "$tracked" "$untracked" | source_git hash-object --stdin
}

validate_source_provenance() {
  [[ "$SOURCE_PROVENANCE_ROOT" == /* && "$SOURCE_PROVENANCE_ROOT" != *$'\n'* ]] || {
    echo "source provenance root must be a non-empty absolute path" >&2
    return 1
  }
  [[ "$SOURCE_PROVENANCE_HEAD" =~ ^[0-9a-f]{40}$ || "$SOURCE_PROVENANCE_HEAD" =~ ^[0-9a-f]{64}$ ]] || {
    echo "source provenance head must be a lowercase Git object ID" >&2
    return 1
  }
  [[ "$SOURCE_PROVENANCE_DIRTY" == true || "$SOURCE_PROVENANCE_DIRTY" == false ]] || {
    echo "source provenance dirty flag must be true or false" >&2
    return 1
  }
  [[ "$SOURCE_PROVENANCE_FINGERPRINT" =~ ^[0-9a-f]{40}$ || "$SOURCE_PROVENANCE_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] || {
    echo "source provenance fingerprint must be a lowercase Git object ID" >&2
    return 1
  }
}

load_source_provenance() {
  local root_set="${CATS_SOURCE_PROVENANCE_ROOT+x}"
  local head_set="${CATS_SOURCE_PROVENANCE_HEAD+x}"
  local dirty_set="${CATS_SOURCE_PROVENANCE_DIRTY+x}"
  local fingerprint_set="${CATS_SOURCE_PROVENANCE_FINGERPRINT+x}"

  if [[ -n "$root_set$head_set$dirty_set$fingerprint_set" ]]; then
    [[ "$root_set" == x && "$head_set" == x && "$dirty_set" == x && "$fingerprint_set" == x ]] || {
      echo "source provenance overrides must set root, head, dirty and fingerprint together" >&2
      return 1
    }
    SOURCE_PROVENANCE_ROOT="$CATS_SOURCE_PROVENANCE_ROOT"
    SOURCE_PROVENANCE_HEAD="$CATS_SOURCE_PROVENANCE_HEAD"
    SOURCE_PROVENANCE_DIRTY="$CATS_SOURCE_PROVENANCE_DIRTY"
    SOURCE_PROVENANCE_FINGERPRINT="$CATS_SOURCE_PROVENANCE_FINGERPRINT"
    validate_source_provenance
    return
  fi

  local status
  SOURCE_PROVENANCE_ROOT="$(source_git rev-parse --show-toplevel)" || return 1
  SOURCE_PROVENANCE_HEAD="$(source_git rev-parse HEAD)" || return 1
  status="$(source_git status --porcelain=v1 --untracked-files=all)" || return 1
  SOURCE_PROVENANCE_DIRTY=false
  if [[ -n "$status" ]]; then
    SOURCE_PROVENANCE_DIRTY=true
  fi
  SOURCE_PROVENANCE_FINGERPRINT="$(source_fingerprint)" || return 1
  validate_source_provenance
}

print_source_provenance() {
  echo "==> source provenance"
  printf 'source.root=%s\n' "$SOURCE_PROVENANCE_ROOT"
  printf 'source.head=%s\n' "$SOURCE_PROVENANCE_HEAD"
  printf 'source.dirty=%s\n' "$SOURCE_PROVENANCE_DIRTY"
  printf 'source.fingerprint=%s\n' "$SOURCE_PROVENANCE_FINGERPRINT"
}

run_fmt() {
  echo "==> cargo fmt"
  cargo fmt --all -- --check || return 1
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

run_release_images() {
  echo "==> release Dockerfile targets"
  python3 scripts/check-release-dockerfiles.py || return 1
}

require_tool_version() {
  local executable="$1"
  local expected="$2"
  local install_command="$3"
  local actual

  command -v "$executable" >/dev/null 2>&1 || {
    echo "$executable is required; install it with:" >&2
    echo "  $install_command" >&2
    return 1
  }

  actual="$("$executable" --version)"
  [[ "$actual" == "$expected" ]] || {
    echo "$executable version mismatch: expected '$expected', found '$actual'" >&2
    echo "install the pinned version with:" >&2
    echo "  $install_command" >&2
    return 1
  }
}

run_deps() {
  local lock_before
  local lock_after

  require_tool_version \
    cargo-deny \
    "cargo-deny $CATS_CARGO_DENY_VERSION" \
    "cargo install --locked cargo-deny --version $CATS_CARGO_DENY_VERSION" \
    || return 1
  require_tool_version \
    cargo-machete \
    "$CATS_CARGO_MACHETE_VERSION" \
    "cargo install --locked cargo-machete --version $CATS_CARGO_MACHETE_VERSION" \
    || return 1

  echo "==> cargo deny"
  cargo deny --locked check --hide-inclusion-graph || return 1

  echo "==> cargo machete"
  lock_before="$(cksum Cargo.lock)" || return 1
  cargo machete --with-metadata || return 1
  lock_after="$(cksum Cargo.lock)" || return 1
  [[ "$lock_before" == "$lock_after" ]] || {
    echo "cargo machete changed Cargo.lock; regenerate and commit the lockfile" >&2
    return 1
  }
}

run_build() {
  echo "==> cargo build"
  cargo build --workspace --locked || return 1
}

run_check() {
  echo "==> cargo check"
  cargo check --workspace --all-targets --locked || return 1
}

run_clippy() {
  echo "==> cargo clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings || return 1
}

# The control store is PostgreSQL-only, and its tests refuse to run without a
# server rather than silently skipping. CI provides CATS_TEST_POSTGRES_URL via
# a service container; locally a disposable container covers the test run.
with_test_postgres() {
  if [ -n "${CATS_TEST_POSTGRES_URL:-}" ]; then
    "$@"
    return
  fi
  command -v docker >/dev/null 2>&1 || {
    echo "tests need PostgreSQL: set CATS_TEST_POSTGRES_URL or install docker" >&2
    return 1
  }
  local name="cats-test-pg-$$"
  docker run --rm -d --name "$name" \
    -e POSTGRES_PASSWORD=cats -p 127.0.0.1:0:5432 postgres:16 >/dev/null \
    || return 1
  local status=0
  local port=""
  local i
  for i in $(seq 1 120); do
    if docker exec "$name" pg_isready -U postgres >/dev/null 2>&1; then
      port="$(docker port "$name" 5432/tcp | head -1 | awk -F: '{print $NF}')"
      [ -n "$port" ] && break
    fi
    sleep 0.5
  done
  if [ -z "$port" ]; then
    echo "disposable test PostgreSQL never became ready" >&2
    docker rm -f "$name" >/dev/null 2>&1 || true
    return 1
  fi
  CATS_TEST_POSTGRES_URL="postgres://postgres:cats@127.0.0.1:${port}/postgres" "$@" || status=$?
  docker rm -f "$name" >/dev/null 2>&1 || true
  return "$status"
}

run_test() {
  prepare_native_test_process || return 1
  echo "==> cargo test"
  with_test_postgres cargo test --workspace --locked --no-fail-fast -- --test-threads=4
}

run_doc() {
  echo "==> cargo doc"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked || return 1
}

QUALITY_FAILURES=()

run_collected_stage() {
  local label="$1"
  local runner="$2"
  local stage_status=0

  if "$runner"; then
    echo "==> quality stage passed: $label"
  else
    stage_status=$?
    QUALITY_FAILURES+=("$label (exit $stage_status)")
    echo "==> quality stage failed: $label (exit $stage_status)" >&2
  fi

  # A failed stage is recorded rather than returned so later independent
  # gates still run. run_collected_gates returns the final aggregate status.
  return 0
}

run_collected_gates() {
  local label
  local runner
  local failure

  QUALITY_FAILURES=()
  while [[ "$#" -gt 0 ]]; do
    [[ "$#" -ge 2 ]] || {
      echo "quality gate collector received an incomplete stage" >&2
      return 2
    }
    label="$1"
    runner="$2"
    shift 2
    run_collected_stage "$label" "$runner"
  done

  if [[ "${#QUALITY_FAILURES[@]}" -eq 0 ]]; then
    echo "==> all quality stages passed"
    return 0
  fi

  echo "==> quality stage failures (${#QUALITY_FAILURES[@]}):" >&2
  for failure in "${QUALITY_FAILURES[@]}"; do
    echo "  - $failure" >&2
  done
  return 1
}

run_fast() {
  run_collected_gates \
    fmt run_fmt \
    skills run_skills \
    release-images run_release_images \
    check run_check \
    clippy run_clippy
}

run_full() {
  run_collected_gates \
    fmt run_fmt \
    skills run_skills \
    release-images run_release_images \
    dependencies run_deps \
    check run_check \
    build run_build \
    clippy run_clippy \
    tests run_test \
    rustdoc run_doc
}

run_linux() {
  export CATS_SOURCE_PROVENANCE_ROOT="$SOURCE_PROVENANCE_ROOT"
  export CATS_SOURCE_PROVENANCE_HEAD="$SOURCE_PROVENANCE_HEAD"
  export CATS_SOURCE_PROVENANCE_DIRTY="$SOURCE_PROVENANCE_DIRTY"
  export CATS_SOURCE_PROVENANCE_FINGERPRINT="$SOURCE_PROVENANCE_FINGERPRINT"
  exec "$REPO_ROOT/scripts/linux-gate.sh"
}

load_source_provenance
print_source_provenance

case "${1:-full}" in
  provenance) ;;
  fmt) run_fmt ;;
  skills) run_skills ;;
  deps) run_deps ;;
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
