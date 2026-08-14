#!/usr/bin/env bash
# Source-safe fail-closed state machine for the operator-owned E3 ingress window.
# The sourcing shell supplies the five effect functions named below.
set -euo pipefail

ingress_open_initiated=0
ingress_close_mode=emergency
qualification_transition=not_started
cleanup_in_progress=0
cleanup_completed=0
cleanup_signal_status=0
cleanup_effect_status=0
cleanup_result_status=0
replay_attempted=0
re_cordon_attempted=0
ingress_close_attempted=0
e12_attempted=0

cats_e3_window_record_cleanup_error() {
  local status=$1
  if [[ $status -ne 0 && $cleanup_effect_status -eq 0 ]]; then
    cleanup_effect_status=$status
  fi
}

cats_e3_window_cleanup() {
  if [[ $cleanup_completed -eq 1 ]]; then
    return "$cleanup_result_status"
  fi
  [[ $cleanup_in_progress -eq 0 ]] || return 125
  cleanup_in_progress=1
  set +e
  if [[ $qualification_transition == initiated && $replay_attempted -eq 0 ]]; then
    replay_attempted=1
    cats_e3_window_apply_schedulable_policy
    schedulable_replay_status=$?
    if [[ $schedulable_replay_status -eq 0 ]]; then
      qualification_transition=terminal_schedulable
    else
      cats_e3_window_record_cleanup_error "$schedulable_replay_status"
    fi
  fi
  if [[ $qualification_transition == terminal_schedulable && $re_cordon_attempted -eq 0 ]]; then
    re_cordon_attempted=1
    cats_e3_window_exact_re_cordon
    cats_e3_window_record_cleanup_error "$?"
  fi

  if [[ $ingress_open_initiated -eq 1 && $ingress_close_attempted -eq 0 ]]; then
    ingress_close_attempted=1
    case "$ingress_close_mode" in
      emergency)
        cats_e3_window_emergency_close
        cats_e3_window_record_cleanup_error "$?"
        ;;
      saved)
        cats_e3_window_saved_close
        cats_e3_window_record_cleanup_error "$?"
        ;;
      *) cats_e3_window_record_cleanup_error 125 ;;
    esac
  fi

  if [[ $e12_attempted -eq 0 ]]; then
    e12_attempted=1
    cats_e3_window_run_e12
    cats_e3_window_record_cleanup_error "$?"
  fi
  cleanup_completed=1
  if [[ $cleanup_effect_status -ne 0 ]]; then
    cleanup_result_status=$cleanup_effect_status
  elif [[ $cleanup_signal_status -ne 0 ]]; then
    cleanup_result_status=$cleanup_signal_status
  else
    cleanup_result_status=0
  fi
  cleanup_in_progress=0
  set -e
  return "$cleanup_result_status"
}

cats_e3_window_abort() {
  local window_status=$1 cleanup_status=0
  trap - EXIT
  cats_e3_window_cleanup || cleanup_status=$?
  trap - INT TERM
  if [[ $cleanup_status -ne 0 ]]; then
    exit "$cleanup_status"
  fi
  exit "$window_status"
}

cats_e3_window_handle_signal() {
  local signal_status=$1
  if [[ $cleanup_in_progress -eq 1 ]]; then
    if [[ $cleanup_signal_status -eq 0 ]]; then
      cleanup_signal_status=$signal_status
    fi
    if [[ $cleanup_completed -eq 1 && $cleanup_effect_status -eq 0 ]]; then
      cleanup_result_status=$cleanup_signal_status
    fi
    return 0
  fi
  cats_e3_window_abort "$signal_status"
}

cats_e3_window_install_guard() {
  trap 'cats_e3_window_abort $?' EXIT
  trap 'cats_e3_window_handle_signal 130' INT
  trap 'cats_e3_window_handle_signal 143' TERM
}

cats_e3_window_use_saved_close() {
  [[ $ingress_open_initiated -eq 1 && $ingress_close_mode == emergency ]]
  ingress_close_mode=saved
}

cats_e3_window_finish() {
  local cleanup_status=0
  cats_e3_window_cleanup || cleanup_status=$?
  trap - EXIT INT TERM
  return "$cleanup_status"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

printf '%s\n' 'runtime-cutover-e3-window.sh must be sourced by the reviewed operator runbook' >&2
exit 64
