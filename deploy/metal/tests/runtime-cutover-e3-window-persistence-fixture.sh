#!/usr/bin/env bash
# Fixture for the E3 window persistent journal: full-flow persistence, SIGKILL
# recovery through cats_e3_window_adopt, at-most-once effects across shells,
# operator resolution of an ambiguous effect, single-owner locking and
# fail-closed rejection of corrupt or incomplete journals.  No real effect is
# invoked: every window effect function is a trace-writing stub supplied by
# each child shell, exactly as the sourcing operator shell would supply the
# real terraform/CLI effects.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'usage: %s <runtime-cutover-e3-window.sh> [workdir]\n' "$0" >&2
  exit 64
fi
library=$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")
[[ -f $library ]] || {
  printf 'window library %s not found\n' "$library" >&2
  exit 64
}
workdir=${2:-$(mktemp -d)}
[[ -d $workdir ]] || exit 64

fail() {
  printf 'e3 window persistence fixture: %s\n' "$*" >&2
  exit 1
}

# Runs one operator shell: sources the library, installs trace-writing effect
# stubs, then evaluates the per-case script.  $extra_definitions may override
# a stub before the case script runs.
run_shell() {
  local trace=$1 script=$2 extra_definitions=${3:-:}
  bash -c '
    set -euo pipefail
    fixture_trace=$1
    . "$2"
    cats_e3_window_apply_schedulable_policy() { printf "%s\n" replay >>"$fixture_trace"; }
    cats_e3_window_exact_re_cordon() { printf "%s\n" re-cordon >>"$fixture_trace"; }
    cats_e3_window_emergency_close() { printf "%s\n" emergency-close >>"$fixture_trace"; }
    cats_e3_window_saved_close() { printf "%s\n" saved-close >>"$fixture_trace"; }
    cats_e3_window_run_e12() { printf "%s\n" e12 >>"$fixture_trace"; }
    eval "$3"
    eval "$4"
  ' _ "$trace" "$library" "$extra_definitions" "$script"
}

new_state_dir() {
  local directory=$1
  mkdir -m 0700 "$directory"
}

expect_trace() {
  local trace=$1 expected=$2 label=$3
  [[ $(cat "$trace") == "$expected" ]] ||
    fail "$label trace mismatch: $(tr '\n' ' ' <"$trace")"
}

expect_markers() {
  local state_dir=$1 label=$2 marker
  shift 2
  for marker in "$@"; do
    [[ -f $state_dir/$marker && ! -L $state_dir/$marker ]] ||
      fail "$label missing marker $marker"
  done
}

# --- case 1: normal full flow persists every transition; adopt is a no-op ---
state1=$workdir/case1.state
trace1=$workdir/case1.trace
new_state_dir "$state1"
: >"$trace1"
run_shell "$trace1" "
  cats_e3_window_bind '$state1' fixture-window >/dev/null
  cats_e3_window_install_guard
  cats_e3_window_mark_open_initiated
  cats_e3_window_use_saved_close
  cats_e3_window_mark_qualification_initiated
  cats_e3_window_mark_qualification_terminal
  cats_e3_window_finish
"
expect_trace "$trace1" $'re-cordon\nsaved-close\ne12' 'case1'
expect_markers "$state1" case1 \
  00-window-binding.v1.json \
  10-ingress-open-initiated.v1.json \
  20-ingress-close-mode-saved.v1.json \
  30-qualification-initiated.v1.json \
  40-qualification-terminal-schedulable.v1.json \
  60-re-cordon-attempted.v1.json 61-re-cordon-completed.v1.json \
  70-ingress-close-attempted.v1.json 71-ingress-close-completed.v1.json \
  80-e12-attempted.v1.json 81-e12-completed.v1.json
[[ ! -e $state1/50-replay-attempted.v1.json ]] || fail 'case1 replay must not run'
grep -q '"close_mode":"saved"' "$state1/70-ingress-close-attempted.v1.json" ||
  fail 'case1 close mode not recorded'
summary1=$workdir/case1.summary
run_shell "$trace1" "
  cats_e3_window_adopt '$state1' >'$summary1'
  cats_e3_window_finish
"
expect_trace "$trace1" $'re-cordon\nsaved-close\ne12' 'case1 adopt reran effects;'
grep -q 're-cordon: completed status=0' "$summary1" || fail 'case1 summary lacks re-cordon result'
grep -q 'window is settled' "$summary1" || fail 'case1 summary not settled'

# --- case 2: SIGKILL before cleanup; a fresh shell adopts and converges ---
state2=$workdir/case2.state
trace2=$workdir/case2.trace
new_state_dir "$state2"
: >"$trace2"
status=0
run_shell "$trace2" "
  cats_e3_window_bind '$state2' fixture-window >/dev/null
  cats_e3_window_install_guard
  cats_e3_window_mark_open_initiated
  cats_e3_window_mark_qualification_initiated
  kill -9 \$\$
" || status=$?
[[ $status -eq 137 ]] || fail "case2 expected SIGKILL exit 137, got $status"
[[ ! -s $trace2 ]] || fail 'case2 no effect may run before the kill'
summary2=$workdir/case2.summary
run_shell "$trace2" "
  cats_e3_window_adopt '$state2' >'$summary2'
  cats_e3_window_install_guard
  cats_e3_window_finish
"
grep -q 'ingress_open_initiated=1' "$summary2" || fail 'case2 open intent lost'
grep -q 'qualification_transition=initiated' "$summary2" || fail 'case2 transition lost'
expect_trace "$trace2" $'replay\nre-cordon\nemergency-close\ne12' 'case2 recovery'
expect_markers "$state2" case2 \
  50-replay-attempted.v1.json 51-replay-completed.v1.json \
  40-qualification-terminal-schedulable.v1.json \
  60-re-cordon-attempted.v1.json 61-re-cordon-completed.v1.json \
  70-ingress-close-attempted.v1.json 71-ingress-close-completed.v1.json \
  80-e12-attempted.v1.json 81-e12-completed.v1.json
grep -q '"close_mode":"emergency"' "$state2/70-ingress-close-attempted.v1.json" ||
  fail 'case2 close mode must stay emergency'

# --- case 3: SIGKILL inside an effect leaves it ambiguous; it is never rerun
# --- and only an operator postcondition resolution completes the window ---
state3=$workdir/case3.state
trace3=$workdir/case3.trace
new_state_dir "$state3"
: >"$trace3"
status=0
run_shell "$trace3" "
  cats_e3_window_bind '$state3' fixture-window >/dev/null
  cats_e3_window_install_guard
  cats_e3_window_mark_open_initiated
  cats_e3_window_mark_qualification_initiated
  cats_e3_window_mark_qualification_terminal
  cats_e3_window_finish
" 'cats_e3_window_exact_re_cordon() { printf "%s\n" re-cordon >>"$fixture_trace"; kill -9 $$; }' ||
  status=$?
[[ $status -eq 137 ]] || fail "case3 expected SIGKILL exit 137, got $status"
expect_trace "$trace3" 're-cordon' 'case3 pre-kill'
[[ -f $state3/60-re-cordon-attempted.v1.json ]] || fail 'case3 attempted marker missing'
[[ ! -e $state3/61-re-cordon-completed.v1.json ]] || fail 'case3 completion must be unknown'
summary3=$workdir/case3.summary
run_shell "$trace3" "
  cats_e3_window_adopt '$state3' >'$summary3'
  status=0; cats_e3_window_finish || status=\$?
  [[ \$status -eq 125 ]] || exit 90
  status=0; cats_e3_window_finish || status=\$?
  [[ \$status -eq 125 ]] || exit 91
  cats_e3_window_resolve_effect re-cordon 0 >/dev/null
  status=0; cats_e3_window_finish || status=\$?
  [[ \$status -eq 0 ]] || exit 92
"
grep -q 're-cordon: AMBIGUOUS' "$summary3" || fail 'case3 summary must flag ambiguity'
grep -q 'cats_e3_window_resolve_effect' "$summary3" || fail 'case3 summary must name resolution'
expect_trace "$trace3" $'re-cordon\nemergency-close\ne12' 'case3 at-most-once'
grep -q '"resolution":"operator-postcondition"' "$state3/61-re-cordon-completed.v1.json" ||
  fail 'case3 resolution provenance missing'
run_shell "$trace3" "
  cats_e3_window_adopt '$state3' >/dev/null
  cats_e3_window_finish
"
expect_trace "$trace3" $'re-cordon\nemergency-close\ne12' 'case3 settled window reran effects;'

# --- case 4: one live shell owns a state directory ---
state4=$workdir/case4.state
trace4=$workdir/case4.trace
fifo4=$workdir/case4.fifo
new_state_dir "$state4"
: >"$trace4"
mkfifo "$fifo4"
run_shell "$trace4" "
  cats_e3_window_bind '$state4' fixture-window >/dev/null
  printf 'ready\n' >'$fifo4'
  read -r _ <'$fifo4'
" &
holder=$!
read -r _ <"$fifo4"
status=0
run_shell "$trace4" "cats_e3_window_adopt '$state4' >/dev/null" 2>"$workdir/case4.err" ||
  status=$?
[[ $status -ne 0 ]] || fail 'case4 second shell must not adopt a held window'
grep -q 'another operator shell owns' "$workdir/case4.err" ||
  fail "case4 wrong rejection: $(cat "$workdir/case4.err")"
printf 'go\n' >"$fifo4"
wait "$holder" || fail 'case4 holder shell failed'
run_shell "$trace4" "cats_e3_window_adopt '$state4' >/dev/null" ||
  fail 'case4 adopt must succeed once the holder exits'

# --- case 5: corrupt or incomplete journals fail closed ---
make_settled_state() {
  local state_dir=$1 trace_file=$2
  new_state_dir "$state_dir"
  : >"$trace_file"
  run_shell "$trace_file" "
    cats_e3_window_bind '$state_dir' fixture-window >/dev/null
    cats_e3_window_install_guard
    cats_e3_window_mark_open_initiated
    cats_e3_window_mark_qualification_initiated
    cats_e3_window_mark_qualification_terminal
    cats_e3_window_finish
  "
}

expect_adopt_fails() {
  local state_dir=$1 label=$2 status=0
  run_shell /dev/null "cats_e3_window_adopt '$state_dir' >/dev/null" \
    2>"$workdir/last-adopt.err" || status=$?
  [[ $status -ne 0 ]] || fail "$label adopt must fail closed"
  grep -q 'inspect the state directory manually' "$workdir/last-adopt.err" ||
    grep -q 'cats e3 window' "$workdir/last-adopt.err" ||
    fail "$label adopt failed without a fail-closed message"
}

calibrate_adopt_succeeds() {
  local state_dir=$1 label=$2
  run_shell /dev/null "cats_e3_window_adopt '$state_dir' >/dev/null" ||
    fail "$label calibration adopt must succeed before corruption"
}

# 5a: garbage marker content
state5a=$workdir/case5a.state
make_settled_state "$state5a" "$workdir/case5a.trace"
calibrate_adopt_succeeds "$state5a" case5a
printf 'garbage' >"$state5a/40-qualification-terminal-schedulable.v1.json"
expect_adopt_fails "$state5a" case5a

# 5b: unknown entry in the state directory
state5b=$workdir/case5b.state
make_settled_state "$state5b" "$workdir/case5b.trace"
calibrate_adopt_succeeds "$state5b" case5b
: >"$state5b/rogue.txt"
expect_adopt_fails "$state5b" case5b

# 5c: orphan temporary from an interrupted publish
state5c=$workdir/case5c.state
make_settled_state "$state5c" "$workdir/case5c.trace"
calibrate_adopt_succeeds "$state5c" case5c
printf '{}' >"$state5c/.80-e12-attempted.v1.json.orphan"
chmod 0600 "$state5c/.80-e12-attempted.v1.json.orphan"
expect_adopt_fails "$state5c" case5c

# 5d: completion record without its attempted record
state5d=$workdir/case5d.state
make_settled_state "$state5d" "$workdir/case5d.trace"
calibrate_adopt_succeeds "$state5d" case5d
rm "$state5d/60-re-cordon-attempted.v1.json"
expect_adopt_fails "$state5d" case5d

# 5e: marker mode violation
state5e=$workdir/case5e.state
make_settled_state "$state5e" "$workdir/case5e.trace"
calibrate_adopt_succeeds "$state5e" case5e
chmod 0644 "$state5e/81-e12-completed.v1.json"
expect_adopt_fails "$state5e" case5e

# 5f: adopting an empty directory has nothing to adopt
state5f=$workdir/case5f.state
new_state_dir "$state5f"
expect_adopt_fails "$state5f" case5f

# 5g: rebinding with a different window id is rejected
state5g=$workdir/case5g.state
make_settled_state "$state5g" "$workdir/case5g.trace"
status=0
run_shell /dev/null "cats_e3_window_bind '$state5g' other-window >/dev/null" \
  2>/dev/null || status=$?
[[ $status -ne 0 ]] || fail 'case5g bind must reject a foreign window id'

# --- case 6: completed effects reject duplicate execution and resolution ---
state6=$workdir/case6.state
make_settled_state "$state6" "$workdir/case6.trace"
run_shell "$workdir/case6.trace" "
  cats_e3_window_adopt '$state6' >/dev/null
  status=0; cats_e3_window_resolve_effect e12 0 >/dev/null 2>&1 || status=\$?
  [[ \$status -eq 64 ]] || exit 93
  status=0; cats_e3_window_use_saved_close 2>/dev/null || status=\$?
  [[ \$status -eq 64 ]] || exit 94
"
expect_trace "$workdir/case6.trace" $'re-cordon\nemergency-close\ne12' 'case6'

printf 'e3 window persistence fixture: all cases passed\n'
