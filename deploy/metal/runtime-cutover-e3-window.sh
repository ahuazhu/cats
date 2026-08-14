#!/usr/bin/env bash
# Source-safe fail-closed state machine for the operator-owned E3 ingress window.
# The sourcing shell supplies the five effect functions named below.
set -euo pipefail

ingress_open_initiated=0
ingress_close_mode=emergency
qualification_transition=not_started

cats_e3_window_cleanup() {
  set +e
  re_cordon_status=0
  if [[ $qualification_transition == initiated ]]; then
    cats_e3_window_apply_schedulable_policy
    schedulable_replay_status=$?
    if [[ $schedulable_replay_status -eq 0 ]]; then
      qualification_transition=terminal_schedulable
    else
      re_cordon_status=$schedulable_replay_status
    fi
  fi
  if [[ $qualification_transition == terminal_schedulable ]]; then
    cats_e3_window_exact_re_cordon
    re_cordon_status=$?
  fi

  ingress_close_status=0
  if [[ $ingress_open_initiated -eq 1 ]]; then
    case "$ingress_close_mode" in
      emergency)
        cats_e3_window_emergency_close
        ingress_close_status=$?
        ;;
      saved)
        cats_e3_window_saved_close
        ingress_close_status=$?
        ;;
      *) ingress_close_status=125 ;;
    esac
  fi

  cats_e3_window_run_e12
  fleet_verify_status=$?
  set -e
  [[ $re_cordon_status -eq 0 && $ingress_close_status -eq 0 && $fleet_verify_status -eq 0 ]]
}

cats_e3_window_abort() {
  local window_status=$1 cleanup_status=0
  trap - EXIT INT TERM
  cats_e3_window_cleanup || cleanup_status=$?
  if [[ $cleanup_status -ne 0 ]]; then
    exit "$cleanup_status"
  fi
  exit "$window_status"
}

cats_e3_window_install_guard() {
  trap 'cats_e3_window_abort $?' EXIT
  trap 'cats_e3_window_abort 130' INT
  trap 'cats_e3_window_abort 143' TERM
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
