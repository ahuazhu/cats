#!/usr/bin/env bash
set -euo pipefail

cats_e3_window_fixture_run() {
  local library=$1 trace=$2 checkpoint=$3 failure_mode=$4
  : >"$trace"
  fixture_trace=$trace
  . "$library"

  cats_e3_window_emergency_close() { printf '%s\n' emergency-close >>"$fixture_trace"; }
  cats_e3_window_saved_close() {
    printf '%s\n' saved-close >>"$fixture_trace"
    case "$failure_mode" in
      term-in-saved-close) kill -TERM "$$" ;;
      term-and-close-failure)
        kill -TERM "$$"
        return 57
        ;;
    esac
  }
  cats_e3_window_apply_schedulable_policy() { printf '%s\n' replay >>"$fixture_trace"; }
  cats_e3_window_exact_re_cordon() {
    printf '%s\n' re-cordon >>"$fixture_trace"
    [[ $failure_mode != term-in-re-cordon ]] || kill -TERM "$$"
  }
  cats_e3_window_run_e12() { printf '%s\n' e12 >>"$fixture_trace"; }

  fail_at_checkpoint() {
    [[ $checkpoint == "$1" ]] || return 0
    case "$failure_mode" in
      failure) exit 23 ;;
      term) kill -TERM "$$" ;;
      *) return 64 ;;
    esac
  }

  fixture_state_dir=${trace}.state
  mkdir -m 0700 "$fixture_state_dir"
  cats_e3_window_bind "$fixture_state_dir" fixture-window >/dev/null
  cats_e3_window_install_guard
  cats_e3_window_mark_open_initiated
  printf '%s\n' open >>"$fixture_trace"
  fail_at_checkpoint open
  printf '%s\n' plan >>"$fixture_trace"
  fail_at_checkpoint plan
  printf '%s\n' show >>"$fixture_trace"
  fail_at_checkpoint show
  printf '%s\n' approved >>"$fixture_trace"
  fail_at_checkpoint before-switch
  cats_e3_window_use_saved_close
  fail_at_checkpoint after-switch
  if [[ $checkpoint == finish ]]; then
    cats_e3_window_mark_qualification_initiated
    cats_e3_window_mark_qualification_terminal
    set +e
    cleanup_status=0
    cats_e3_window_finish || cleanup_status=$?
    set -e
    if [[ $cleanup_status -ne 0 ]]; then
      exit "$cleanup_status"
    fi
  fi
  exit 0
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

[[ $# -eq 4 ]] || exit 64
cats_e3_window_fixture_run "$@"
