#!/usr/bin/env bash
# Source-safe fail-closed state machine for the operator-owned E3 ingress window.
# The sourcing shell supplies the five effect functions named below.
#
# Every window transition and every one-shot cleanup effect is journaled into a
# mode-0700 state directory as no-overwrite mode-0600 marker files, written with
# the same atomic pattern as the inner runner's persistent state (same-directory
# 0600 temporary -> fsync -> no-replace link -> directory fsync).  A fresh shell
# recovers the window with cats_e3_window_adopt after the previous operator
# shell was killed; marker existence is the at-most-once authority for the
# replay, re-cordon, ingress-close and E12 cleanup effects.
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

cats_e3_window_state_directory=
cats_e3_window_state_fd=
cats_e3_window_lock_fd=
cats_e3_window_id=
cats_e3_window_replay_state=none
cats_e3_window_replay_status=
cats_e3_window_re_cordon_state=none
cats_e3_window_re_cordon_status=
cats_e3_window_ingress_close_state=none
cats_e3_window_ingress_close_status=
cats_e3_window_e12_state=none
cats_e3_window_e12_status=

cats_e3_window_error() {
  printf 'cats e3 window: %s\n' "$*" >&2
}

cats_e3_window_require_state() {
  if [[ -z $cats_e3_window_state_directory || -z $cats_e3_window_lock_fd ]]; then
    cats_e3_window_error \
      'no persistent window state is bound; run cats_e3_window_bind or cats_e3_window_adopt first'
    return 64
  fi
}

cats_e3_window_release_state() {
  if [[ -n $cats_e3_window_lock_fd ]]; then
    exec {cats_e3_window_lock_fd}>&- || true
    cats_e3_window_lock_fd=
  fi
  if [[ -n $cats_e3_window_state_fd ]]; then
    exec {cats_e3_window_state_fd}<&- || true
    cats_e3_window_state_fd=
  fi
  cats_e3_window_state_directory=
  cats_e3_window_id=
}

# Opens and pins the state directory fd, then binds the journal flock to a
# shell-owned descriptor so one live shell owns the window for its lifetime.
cats_e3_window_open_state() {
  local directory=$1 lock_identity
  if [[ $directory != /* ]]; then
    cats_e3_window_error 'state directory must be an absolute path'
    return 64
  fi
  cats_e3_window_release_state
  if [[ -L $directory || ! -d $directory ]]; then
    cats_e3_window_error "state directory $directory is not a non-symlink directory"
    return 64
  fi
  if ! exec {cats_e3_window_state_fd}<"$directory"; then
    cats_e3_window_state_fd=
    cats_e3_window_error "state directory $directory could not be opened"
    return 64
  fi
  if ! python3 - "$cats_e3_window_state_fd" <<'PY'
import os
import stat
import sys

value = os.fstat(int(sys.argv[1]))
if not stat.S_ISDIR(value.st_mode):
    raise SystemExit(1)
if value.st_uid != os.geteuid():
    raise SystemExit(1)
if os.geteuid() == 0 and value.st_gid != 0:
    raise SystemExit(1)
if stat.S_IMODE(value.st_mode) != 0o700:
    raise SystemExit(1)
PY
  then
    cats_e3_window_release_state
    cats_e3_window_error \
      "state directory $directory must be a mode-0700 directory owned by the effective user"
    return 64
  fi
  if ! lock_identity=$(python3 - "$cats_e3_window_state_fd" <<'PY'
import os
import stat
import sys

directory_fd = int(sys.argv[1])
flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(".cats-e3-window.lock", flags, 0o600, dir_fd=directory_fd)
try:
    os.fchmod(descriptor, 0o600)
    value = os.fstat(descriptor)
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or (os.geteuid() == 0 and value.st_gid != 0)
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
    ):
        raise SystemExit(1)
    os.fsync(descriptor)
    os.fsync(directory_fd)
    print(f"{value.st_dev}:{value.st_ino}")
finally:
    os.close(descriptor)
PY
  ); then
    cats_e3_window_release_state
    cats_e3_window_error 'window lock file is not protected single-link state'
    return 64
  fi
  if ! exec {cats_e3_window_lock_fd}<>"$directory/.cats-e3-window.lock"; then
    cats_e3_window_lock_fd=
    cats_e3_window_release_state
    cats_e3_window_error 'window lock file could not be bound to a shell descriptor'
    return 64
  fi
  # fcntl.flock on the shell-inherited descriptor leaves the lock held by the
  # shell's open file description for the life of this operator shell.
  if ! python3 - "$cats_e3_window_lock_fd" "$lock_identity" <<'PY'
import fcntl
import os
import stat
import sys

descriptor = int(sys.argv[1])
value = os.fstat(descriptor)
if (
    not stat.S_ISREG(value.st_mode)
    or value.st_uid != os.geteuid()
    or (os.geteuid() == 0 and value.st_gid != 0)
    or stat.S_IMODE(value.st_mode) != 0o600
    or value.st_nlink != 1
    or f"{value.st_dev}:{value.st_ino}" != sys.argv[2]
):
    raise SystemExit(1)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    raise SystemExit(2)
PY
  then
    cats_e3_window_release_state
    cats_e3_window_error 'another operator shell owns this window state directory'
    return 65
  fi
  cats_e3_window_state_directory=$directory
}

# Publishes one journal marker with the inner runner's atomic no-overwrite
# pattern.  Republishing byte-identical content succeeds; conflicting content
# fails closed.
cats_e3_window_publish_marker() {
  local name=$1 event=$2
  shift 2
  cats_e3_window_require_state || return 64
  python3 - "$cats_e3_window_state_fd" "$cats_e3_window_state_directory" \
    "$name" "$cats_e3_window_id" "$event" "$@" <<'PY'
import json
import os
import re
import stat
import sys
import tempfile

inherited_directory_fd = int(sys.argv[1])
directory = sys.argv[2]
name = sys.argv[3]
window_id = sys.argv[4]
event = sys.argv[5]
extras = sys.argv[6:]

MARKERS = {
    "00-window-binding.v1.json": "binding",
    "10-ingress-open-initiated.v1.json": "ingress-open-initiated",
    "20-ingress-close-mode-saved.v1.json": "ingress-close-mode-saved",
    "30-qualification-initiated.v1.json": "qualification-initiated",
    "40-qualification-terminal-schedulable.v1.json": "qualification-terminal-schedulable",
    "50-replay-attempted.v1.json": "replay-attempted",
    "51-replay-completed.v1.json": "replay-completed",
    "60-re-cordon-attempted.v1.json": "re-cordon-attempted",
    "61-re-cordon-completed.v1.json": "re-cordon-completed",
    "70-ingress-close-attempted.v1.json": "ingress-close-attempted",
    "71-ingress-close-completed.v1.json": "ingress-close-completed",
    "80-e12-attempted.v1.json": "e12-attempted",
    "81-e12-completed.v1.json": "e12-completed",
}
EXTRA_KEYS = {
    "51-replay-completed.v1.json": {"status", "resolution"},
    "61-re-cordon-completed.v1.json": {"status", "resolution"},
    "70-ingress-close-attempted.v1.json": {"close_mode"},
    "71-ingress-close-completed.v1.json": {"status", "resolution"},
    "81-e12-completed.v1.json": {"status", "resolution"},
}

if name not in MARKERS or MARKERS[name] != event:
    raise SystemExit(1)
if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", window_id):
    raise SystemExit(1)
if len(extras) % 2 != 0:
    raise SystemExit(1)
entry_extras = dict(zip(extras[0::2], extras[1::2]))
if len(entry_extras) * 2 != len(extras):
    raise SystemExit(1)
if set(entry_extras) != EXTRA_KEYS.get(name, set()):
    raise SystemExit(1)
if "status" in entry_extras:
    if not re.fullmatch(r"0|[1-9][0-9]{0,2}", entry_extras["status"]):
        raise SystemExit(1)
    status = int(entry_extras["status"])
    if status > 255:
        raise SystemExit(1)
    entry_extras["status"] = status
if entry_extras.get("resolution") not in (None, "effect-return", "operator-postcondition"):
    raise SystemExit(1)
if entry_extras.get("close_mode") not in (None, "emergency", "saved"):
    raise SystemExit(1)

if name == "00-window-binding.v1.json":
    entry = {"kind": "cats.e3-window-binding.v1", "version": 1, "window_id": window_id}
else:
    entry = {
        "event": event,
        "kind": "cats.e3-window-journal-entry.v1",
        "version": 1,
        "window_id": window_id,
    }
    entry.update(entry_extras)
expected = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode()

directory_fd = os.dup(inherited_directory_fd)
effective_uid = os.geteuid()
prefix = f".{name}."


def actor_owned(value):
    return value.st_uid == effective_uid and (effective_uid != 0 or value.st_gid == 0)


def read_existing():
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not actor_owned(before)
            or before.st_nlink not in {1, 2}
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != len(expected)
        ):
            raise SystemExit(1)
        if before.st_nlink == 2:
            siblings = []
            # Linux fdopendir inherits the descriptor offset (macOS rewinds);
            # rewind so the sibling scan sees the whole directory.
            os.lseek(directory_fd, 0, os.SEEK_SET)
            for candidate in os.listdir(directory_fd):
                if not candidate.startswith(prefix):
                    continue
                metadata = os.stat(candidate, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == (before.st_dev, before.st_ino)
                ):
                    siblings.append(candidate)
            if len(siblings) != 1:
                raise SystemExit(1)
            os.unlink(siblings[0], dir_fd=directory_fd)
            os.fsync(directory_fd)
            before = os.fstat(descriptor)
            if before.st_nlink != 1:
                raise SystemExit(1)
        data = b""
        while len(data) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(data))
            if not chunk:
                raise SystemExit(1)
            data += chunk
        if os.read(descriptor, 1) or data != expected:
            raise SystemExit(1)
    finally:
        os.close(descriptor)


temporary_fd = -1
temporary_name = None
try:
    try:
        read_existing()
    except FileNotFoundError:
        temporary_fd, temporary_name = tempfile.mkstemp(prefix=prefix, dir=directory)
        os.fchmod(temporary_fd, 0o600)
        offset = 0
        while offset < len(expected):
            offset += os.write(temporary_fd, expected[offset:])
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        try:
            os.link(
                temporary_name,
                name,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            read_existing()
        else:
            os.unlink(temporary_name)
            temporary_name = None
            os.fsync(directory_fd)
            read_existing()
finally:
    if temporary_fd >= 0:
        os.close(temporary_fd)
    if temporary_name is not None:
        try:
            os.unlink(temporary_name)
            os.fsync(directory_fd)
        except FileNotFoundError:
            pass
    os.close(directory_fd)
PY
}

# Validates the complete journal and rebuilds the in-memory window state.
# Any unknown entry, non-canonical marker, orphan temporary or missing
# prerequisite fails closed; the only self-healing is removing the leftover
# second link of an already-durable marker, exactly like the inner runner.
cats_e3_window_load_state() {
  local output line key value extra slot recovered_window_id=
  if ! output=$(python3 - "$cats_e3_window_state_fd" <<'PY'
import json
import os
import re
import stat
import sys

MARKERS = {
    "00-window-binding.v1.json": "binding",
    "10-ingress-open-initiated.v1.json": "ingress-open-initiated",
    "20-ingress-close-mode-saved.v1.json": "ingress-close-mode-saved",
    "30-qualification-initiated.v1.json": "qualification-initiated",
    "40-qualification-terminal-schedulable.v1.json": "qualification-terminal-schedulable",
    "50-replay-attempted.v1.json": "replay-attempted",
    "51-replay-completed.v1.json": "replay-completed",
    "60-re-cordon-attempted.v1.json": "re-cordon-attempted",
    "61-re-cordon-completed.v1.json": "re-cordon-completed",
    "70-ingress-close-attempted.v1.json": "ingress-close-attempted",
    "71-ingress-close-completed.v1.json": "ingress-close-completed",
    "80-e12-attempted.v1.json": "e12-attempted",
    "81-e12-completed.v1.json": "e12-completed",
}
EXTRA_KEYS = {
    "51-replay-completed.v1.json": {"status", "resolution"},
    "61-re-cordon-completed.v1.json": {"status", "resolution"},
    "70-ingress-close-attempted.v1.json": {"close_mode"},
    "71-ingress-close-completed.v1.json": {"status", "resolution"},
    "81-e12-completed.v1.json": {"status", "resolution"},
}
PREREQUISITES = {
    "20-ingress-close-mode-saved.v1.json": ["10-ingress-open-initiated.v1.json"],
    "40-qualification-terminal-schedulable.v1.json": ["30-qualification-initiated.v1.json"],
    "50-replay-attempted.v1.json": ["30-qualification-initiated.v1.json"],
    "51-replay-completed.v1.json": ["50-replay-attempted.v1.json"],
    "60-re-cordon-attempted.v1.json": ["40-qualification-terminal-schedulable.v1.json"],
    "61-re-cordon-completed.v1.json": ["60-re-cordon-attempted.v1.json"],
    "70-ingress-close-attempted.v1.json": ["10-ingress-open-initiated.v1.json"],
    "71-ingress-close-completed.v1.json": ["70-ingress-close-attempted.v1.json"],
    "81-e12-completed.v1.json": ["80-e12-attempted.v1.json"],
}
EFFECTS = [
    ("replay", "50-replay-attempted.v1.json", "51-replay-completed.v1.json"),
    ("re_cordon", "60-re-cordon-attempted.v1.json", "61-re-cordon-completed.v1.json"),
    ("ingress_close", "70-ingress-close-attempted.v1.json", "71-ingress-close-completed.v1.json"),
    ("e12", "80-e12-attempted.v1.json", "81-e12-completed.v1.json"),
]
LOCK = ".cats-e3-window.lock"
BINDING = "00-window-binding.v1.json"

directory_fd = os.dup(int(sys.argv[1]))
# Linux fdopendir inherits the descriptor offset (macOS rewinds); rewind so
# the marker scan sees the whole directory.
os.lseek(directory_fd, 0, os.SEEK_SET)
effective_uid = os.geteuid()


def fail(message):
    print(f"window journal: {message}", file=sys.stderr)
    raise SystemExit(1)


def actor_owned(value):
    return value.st_uid == effective_uid and (effective_uid != 0 or value.st_gid == 0)


present = []
temporaries = {}
for candidate in os.listdir(directory_fd):
    if candidate == LOCK:
        continue
    if candidate in MARKERS:
        present.append(candidate)
        continue
    owner = None
    for known in MARKERS:
        if candidate.startswith(f".{known}."):
            owner = known
            break
    if owner is None:
        fail(f"unexpected entry {candidate!r} in the window state directory")
    temporaries.setdefault(owner, []).append(candidate)

contents = {}
for name in sorted(present):
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(value.st_mode)
            or not actor_owned(value)
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_nlink not in {1, 2}
            or not 1 <= value.st_size <= 4096
        ):
            fail(f"marker {name} fails ownership, mode, link or size validation")
        if value.st_nlink == 2:
            group = temporaries.get(name, [])
            siblings = []
            for candidate in group:
                metadata = os.stat(candidate, dir_fd=directory_fd, follow_symlinks=False)
                if (metadata.st_dev, metadata.st_ino) == (value.st_dev, value.st_ino):
                    siblings.append(candidate)
            if len(group) != 1 or len(siblings) != 1:
                fail(f"marker {name} has an unresolvable interrupted publish")
            os.unlink(siblings[0], dir_fd=directory_fd)
            os.fsync(directory_fd)
            temporaries.pop(name)
            after = os.fstat(descriptor)
            if after.st_nlink != 1 or (after.st_dev, after.st_ino) != (
                value.st_dev,
                value.st_ino,
            ):
                fail(f"marker {name} changed while its second link was removed")
            value = after
        data = b""
        while len(data) < value.st_size:
            chunk = os.read(descriptor, value.st_size - len(data))
            if not chunk:
                fail(f"marker {name} could not be read completely")
            data += chunk
        if os.read(descriptor, 1):
            fail(f"marker {name} grew while it was read")
        contents[name] = data
    finally:
        os.close(descriptor)

if temporaries:
    orphans = sorted(entry for group in temporaries.values() for entry in group)
    fail(
        "orphan temporary journal entries "
        f"{orphans}; a marker publish was interrupted before it became durable - "
        "inspect the state directory manually"
    )

if BINDING not in contents:
    fail("no window binding marker; nothing to adopt")


def decode(name):
    data = contents[name]
    try:
        loaded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        fail(f"marker {name} is not valid JSON")
    if (json.dumps(loaded, sort_keys=True, separators=(",", ":")) + "\n").encode() != data:
        fail(f"marker {name} is not canonical")
    if not isinstance(loaded, dict):
        fail(f"marker {name} is not a JSON object")
    return loaded


binding = decode(BINDING)
if set(binding) != {"kind", "version", "window_id"}:
    fail("window binding has unexpected keys")
if binding["kind"] != "cats.e3-window-binding.v1" or binding["version"] != 1:
    fail("window binding kind/version mismatch")
window_id = binding["window_id"]
if not isinstance(window_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", window_id):
    fail("window binding id is not canonical")

entries = {}
for name in sorted(contents):
    if name == BINDING:
        continue
    entry = decode(name)
    expected_keys = {"event", "kind", "version", "window_id"} | EXTRA_KEYS.get(name, set())
    if set(entry) != expected_keys:
        fail(f"marker {name} has unexpected keys")
    if (
        entry["kind"] != "cats.e3-window-journal-entry.v1"
        or entry["version"] != 1
        or entry["event"] != MARKERS[name]
        or entry["window_id"] != window_id
    ):
        fail(f"marker {name} does not belong to this window")
    if "status" in entry:
        status = entry["status"]
        if isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 255:
            fail(f"marker {name} has a non-integer or out-of-range status")
    if "resolution" in entry and entry["resolution"] not in {
        "effect-return",
        "operator-postcondition",
    }:
        fail(f"marker {name} has an unknown resolution")
    if "close_mode" in entry and entry["close_mode"] not in {"emergency", "saved"}:
        fail(f"marker {name} has an unknown close mode")
    entries[name] = entry

for name, requirements in PREREQUISITES.items():
    if name not in entries:
        continue
    for requirement in requirements:
        if requirement not in entries:
            fail(f"marker {name} is present without its prerequisite {requirement}")

close_attempted = entries.get("70-ingress-close-attempted.v1.json")
if close_attempted is not None:
    expected_mode = "saved" if "20-ingress-close-mode-saved.v1.json" in entries else "emergency"
    if close_attempted["close_mode"] != expected_mode:
        fail("recorded ingress close mode disagrees with the close-mode journal")

open_initiated = 1 if "10-ingress-open-initiated.v1.json" in entries else 0
close_mode = "saved" if "20-ingress-close-mode-saved.v1.json" in entries else "emergency"
if "40-qualification-terminal-schedulable.v1.json" in entries:
    transition = "terminal_schedulable"
elif "30-qualification-initiated.v1.json" in entries:
    transition = "initiated"
else:
    transition = "not_started"

print(f"window_id {window_id}")
print(f"ingress_open_initiated {open_initiated}")
print(f"ingress_close_mode {close_mode}")
print(f"qualification_transition {transition}")
for slot, attempted_name, completed_name in EFFECTS:
    if completed_name in entries:
        print(f"effect_{slot} completed {entries[completed_name]['status']}")
    elif attempted_name in entries:
        print(f"effect_{slot} ambiguous")
    else:
        print(f"effect_{slot} none")
os.close(directory_fd)
PY
  ); then
    cats_e3_window_error \
      'persistent window journal is corrupt or incomplete; failing closed - inspect the state directory manually'
    return 65
  fi
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
  while IFS=' ' read -r key value extra; do
    [[ -n $key ]] || continue
    case "$key" in
      window_id)
        if [[ ! $value =~ ^[a-z0-9][a-z0-9._-]{0,63}$ || -n $extra ]]; then
          cats_e3_window_error 'recovered window id is not canonical'
          return 65
        fi
        recovered_window_id=$value
        ;;
      ingress_open_initiated)
        case "$value" in
          0 | 1) ingress_open_initiated=$value ;;
          *) return 65 ;;
        esac
        ;;
      ingress_close_mode)
        case "$value" in
          emergency | saved) ingress_close_mode=$value ;;
          *) return 65 ;;
        esac
        ;;
      qualification_transition)
        case "$value" in
          not_started | initiated | terminal_schedulable) qualification_transition=$value ;;
          *) return 65 ;;
        esac
        ;;
      effect_replay | effect_re_cordon | effect_ingress_close | effect_e12)
        slot=${key#effect_}
        case "$value" in
          none)
            printf -v "cats_e3_window_${slot}_state" '%s' none
            printf -v "cats_e3_window_${slot}_status" '%s' ''
            printf -v "${slot}_attempted" '%s' 0
            ;;
          ambiguous)
            printf -v "cats_e3_window_${slot}_state" '%s' ambiguous
            printf -v "cats_e3_window_${slot}_status" '%s' ''
            printf -v "${slot}_attempted" '%s' 1
            ;;
          completed)
            if [[ ! $extra =~ ^(0|[1-9][0-9]{0,2})$ || $extra -gt 255 ]]; then
              return 65
            fi
            printf -v "cats_e3_window_${slot}_state" '%s' completed
            printf -v "cats_e3_window_${slot}_status" '%s' "$extra"
            printf -v "${slot}_attempted" '%s' 1
            ;;
          *) return 65 ;;
        esac
        ;;
      *)
        cats_e3_window_error 'recovered journal state has an unexpected field'
        return 65
        ;;
    esac
  done <<<"$output"
  if [[ -z $recovered_window_id ]]; then
    cats_e3_window_error 'recovered journal state has no window id'
    return 65
  fi
  cats_e3_window_id=$recovered_window_id
  # Deterministic consequence, not a guess: a durably successful replay means
  # the qualification transition is terminal even when the terminal marker was
  # lost between the two publishes.
  if [[ $cats_e3_window_replay_state == completed && $cats_e3_window_replay_status -eq 0 &&
    $qualification_transition == initiated ]]; then
    if ! cats_e3_window_publish_marker \
      40-qualification-terminal-schedulable.v1.json qualification-terminal-schedulable; then
      cats_e3_window_error 'could not persist the healed terminal-schedulable transition'
      return 65
    fi
    qualification_transition=terminal_schedulable
  fi
}

cats_e3_window_slot_line() {
  local slot=$1 state_var status_var
  state_var=cats_e3_window_${slot}_state
  status_var=cats_e3_window_${slot}_status
  case "${!state_var}" in
    none) printf '  %s: not attempted\n' "${slot//_/-}" ;;
    ambiguous) printf '  %s: AMBIGUOUS - attempted without a completion record\n' "${slot//_/-}" ;;
    completed) printf '  %s: completed status=%s\n' "${slot//_/-}" "${!status_var}" ;;
  esac
}

cats_e3_window_summary() {
  cats_e3_window_require_state || return 64
  local slot ambiguous=0 pending=0
  printf 'E3 window %s adopted from %s\n' "$cats_e3_window_id" "$cats_e3_window_state_directory"
  printf '  ingress_open_initiated=%s\n' "$ingress_open_initiated"
  printf '  ingress_close_mode=%s\n' "$ingress_close_mode"
  printf '  qualification_transition=%s\n' "$qualification_transition"
  for slot in replay re_cordon ingress_close e12; do
    cats_e3_window_slot_line "$slot"
    local state_var=cats_e3_window_${slot}_state
    [[ ${!state_var} != ambiguous ]] || ambiguous=1
  done
  [[ $qualification_transition != initiated || $cats_e3_window_replay_state != none ]] || pending=1
  [[ $qualification_transition != terminal_schedulable || $cats_e3_window_re_cordon_state != none ]] || pending=1
  [[ $ingress_open_initiated -ne 1 || $cats_e3_window_ingress_close_state != none ]] || pending=1
  [[ $cats_e3_window_e12_state != none ]] || pending=1
  printf 'Allowed next actions:\n'
  if [[ $ambiguous -eq 1 ]]; then
    printf '  - discover each AMBIGUOUS effect postcondition manually, then record it with\n'
    printf '    cats_e3_window_resolve_effect <replay|re-cordon|ingress-close|e12> <exit-status>\n'
  fi
  if [[ $ingress_open_initiated -eq 0 && $qualification_transition == not_started &&
    $cats_e3_window_e12_state == none && $ambiguous -eq 0 ]]; then
    printf '  - fresh window: cats_e3_window_install_guard, then run the runbook mainline\n'
  elif [[ $pending -eq 1 || $ambiguous -eq 1 ]]; then
    printf '  - cats_e3_window_install_guard, then resume the runbook mainline where the journal\n'
    printf '    stopped, or run cats_e3_window_finish to drive the remaining cleanup ladder\n'
  else
    printf '  - window is settled; every recorded effect is complete and none will rerun\n'
  fi
}

cats_e3_window_bind() {
  local directory=${1:-} window_id=${2:-}
  if [[ -z $directory || -z $window_id ]]; then
    cats_e3_window_error 'usage: cats_e3_window_bind <state-directory> <window-id>'
    return 64
  fi
  if [[ ! $window_id =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
    cats_e3_window_error 'window id must be lowercase [a-z0-9][a-z0-9._-]{0,63}'
    return 64
  fi
  cats_e3_window_open_state "$directory" || return
  cats_e3_window_id=$window_id
  if ! cats_e3_window_publish_marker 00-window-binding.v1.json binding; then
    cats_e3_window_error \
      'window binding could not be published; a different window may already own this state directory'
    cats_e3_window_release_state
    return 65
  fi
  if ! cats_e3_window_load_state; then
    cats_e3_window_release_state
    return 65
  fi
  if [[ $cats_e3_window_id != "$window_id" ]]; then
    cats_e3_window_error 'recovered window id does not match the requested binding'
    cats_e3_window_release_state
    return 65
  fi
  cats_e3_window_summary
}

cats_e3_window_adopt() {
  local directory=${1:-}
  if [[ -z $directory ]]; then
    cats_e3_window_error 'usage: cats_e3_window_adopt <state-directory>'
    return 64
  fi
  cats_e3_window_open_state "$directory" || return
  if ! cats_e3_window_load_state; then
    cats_e3_window_release_state
    return 65
  fi
  cats_e3_window_summary
}

cats_e3_window_mark_open_initiated() {
  cats_e3_window_require_state || return 64
  [[ $ingress_open_initiated -eq 0 ]] || return 0
  if ! cats_e3_window_publish_marker 10-ingress-open-initiated.v1.json ingress-open-initiated; then
    cats_e3_window_error 'refusing to run the open effect without a durable open-initiated record'
    return 65
  fi
  ingress_open_initiated=1
}

cats_e3_window_mark_qualification_initiated() {
  cats_e3_window_require_state || return 64
  case "$qualification_transition" in
    initiated) return 0 ;;
    not_started) ;;
    *)
      cats_e3_window_error "qualification transition is already $qualification_transition"
      return 64
      ;;
  esac
  if ! cats_e3_window_publish_marker 30-qualification-initiated.v1.json qualification-initiated; then
    cats_e3_window_error 'refusing the schedulable apply without a durable initiated record'
    return 65
  fi
  qualification_transition=initiated
}

cats_e3_window_mark_qualification_terminal() {
  cats_e3_window_require_state || return 64
  case "$qualification_transition" in
    terminal_schedulable) return 0 ;;
    initiated) ;;
    *)
      cats_e3_window_error 'qualification transition must be initiated before it becomes terminal'
      return 64
      ;;
  esac
  if ! cats_e3_window_publish_marker \
    40-qualification-terminal-schedulable.v1.json qualification-terminal-schedulable; then
    cats_e3_window_error 'refusing to continue without a durable terminal-schedulable record'
    return 65
  fi
  qualification_transition=terminal_schedulable
}

cats_e3_window_use_saved_close() {
  cats_e3_window_require_state || return 64
  if [[ $ingress_open_initiated -ne 1 ]]; then
    cats_e3_window_error 'the saved close plan only applies after the open effect was initiated'
    return 64
  fi
  [[ $ingress_close_mode != saved ]] || return 0
  if [[ $ingress_close_mode != emergency || $ingress_close_attempted -ne 0 ||
    $cats_e3_window_ingress_close_state != none ]]; then
    cats_e3_window_error 'ingress close was already attempted; the close mode is frozen'
    return 64
  fi
  if ! cats_e3_window_publish_marker \
    20-ingress-close-mode-saved.v1.json ingress-close-mode-saved; then
    cats_e3_window_error 'refusing to switch to the saved close plan without a durable record'
    return 65
  fi
  ingress_close_mode=saved
}

# Records an operator-discovered outcome for an effect whose attempted marker
# exists without a completion record.  This is postcondition discovery, not a
# retry: cleanup never reruns an attempted effect.
cats_e3_window_resolve_effect() {
  local effect=${1:-} status=${2:-} slot state_var
  cats_e3_window_require_state || return 64
  if [[ $cleanup_in_progress -ne 0 ]]; then
    return 125
  fi
  case "$effect" in
    replay) slot=replay ;;
    re-cordon | re_cordon) slot=re_cordon ;;
    ingress-close | ingress_close) slot=ingress_close ;;
    e12) slot=e12 ;;
    *)
      cats_e3_window_error 'usage: cats_e3_window_resolve_effect <replay|re-cordon|ingress-close|e12> <exit-status>'
      return 64
      ;;
  esac
  if [[ ! $status =~ ^(0|[1-9][0-9]{0,2})$ || $status -gt 255 ]]; then
    cats_e3_window_error 'the discovered exit status must be an integer in 0..255'
    return 64
  fi
  state_var=cats_e3_window_${slot}_state
  if [[ ${!state_var} != ambiguous ]]; then
    cats_e3_window_error "effect ${slot//_/-} is not ambiguous; nothing to resolve"
    return 64
  fi
  case "$slot" in
    replay)
      cats_e3_window_publish_marker 51-replay-completed.v1.json replay-completed \
        status "$status" resolution operator-postcondition
      ;;
    re_cordon)
      cats_e3_window_publish_marker 61-re-cordon-completed.v1.json re-cordon-completed \
        status "$status" resolution operator-postcondition
      ;;
    ingress_close)
      cats_e3_window_publish_marker 71-ingress-close-completed.v1.json ingress-close-completed \
        status "$status" resolution operator-postcondition
      ;;
    e12)
      cats_e3_window_publish_marker 81-e12-completed.v1.json e12-completed \
        status "$status" resolution operator-postcondition
      ;;
  esac || {
    cats_e3_window_error 'the resolved completion record could not be persisted'
    return 65
  }
  printf -v "$state_var" '%s' completed
  printf -v "cats_e3_window_${slot}_status" '%s' "$status"
  if [[ $slot == replay && $status -eq 0 && $qualification_transition == initiated ]]; then
    if ! cats_e3_window_publish_marker \
      40-qualification-terminal-schedulable.v1.json qualification-terminal-schedulable; then
      cats_e3_window_error 'could not persist the terminal-schedulable transition after replay success'
      return 65
    fi
    qualification_transition=terminal_schedulable
  fi
  cleanup_completed=0
  cleanup_effect_status=0
  cleanup_result_status=0
  printf 'effect %s resolved with status %s; run cats_e3_window_finish to continue cleanup\n' \
    "${slot//_/-}" "$status"
}

cats_e3_window_record_cleanup_error() {
  local status=$1
  if [[ $status -ne 0 && $cleanup_effect_status -eq 0 ]]; then
    cleanup_effect_status=$status
  fi
}

# One cleanup slot: the attempted marker is the write-ahead record, published
# before the effect runs; the completed marker freezes the effect status.  A
# recovered ambiguous slot is never rerun.
cats_e3_window_cleanup_slot() {
  local slot=$1 state_var status_var attempted_var effect_status publish_status
  state_var=cats_e3_window_${slot}_state
  status_var=cats_e3_window_${slot}_status
  attempted_var=${slot}_attempted
  case "${!state_var}" in
    completed)
      printf -v "$attempted_var" '%s' 1
      cats_e3_window_record_cleanup_error "${!status_var}"
      return 0
      ;;
    ambiguous)
      printf -v "$attempted_var" '%s' 1
      cats_e3_window_error "effect ${slot//_/-} was attempted with an unknown outcome; discover its postcondition and record it with cats_e3_window_resolve_effect ${slot//_/-} <exit-status>"
      cats_e3_window_record_cleanup_error 125
      return 0
      ;;
    none) ;;
    *)
      cats_e3_window_record_cleanup_error 125
      return 0
      ;;
  esac
  if [[ ${!attempted_var} -ne 0 ]]; then
    # Attempted earlier in this shell without a durable record; ambiguous.
    cats_e3_window_record_cleanup_error 125
    return 0
  fi
  printf -v "$attempted_var" '%s' 1
  if [[ $slot == ingress_close ]]; then
    case "$ingress_close_mode" in
      emergency | saved) ;;
      *)
        cats_e3_window_record_cleanup_error 125
        return 0
        ;;
    esac
  fi
  case "$slot" in
    replay) cats_e3_window_publish_marker 50-replay-attempted.v1.json replay-attempted ;;
    re_cordon) cats_e3_window_publish_marker 60-re-cordon-attempted.v1.json re-cordon-attempted ;;
    ingress_close)
      cats_e3_window_publish_marker 70-ingress-close-attempted.v1.json ingress-close-attempted \
        close_mode "$ingress_close_mode"
      ;;
    e12) cats_e3_window_publish_marker 80-e12-attempted.v1.json e12-attempted ;;
  esac
  publish_status=$?
  if [[ $publish_status -ne 0 ]]; then
    cats_e3_window_error "cannot persist the ${slot//_/-} attempt record; refusing to run the effect"
    cats_e3_window_record_cleanup_error 125
    return 0
  fi
  printf -v "$state_var" '%s' ambiguous
  case "$slot" in
    replay) cats_e3_window_apply_schedulable_policy ;;
    re_cordon) cats_e3_window_exact_re_cordon ;;
    ingress_close)
      case "$ingress_close_mode" in
        emergency) cats_e3_window_emergency_close ;;
        saved) cats_e3_window_saved_close ;;
      esac
      ;;
    e12) cats_e3_window_run_e12 ;;
  esac
  effect_status=$?
  case "$slot" in
    replay)
      cats_e3_window_publish_marker 51-replay-completed.v1.json replay-completed \
        status "$effect_status" resolution effect-return
      ;;
    re_cordon)
      cats_e3_window_publish_marker 61-re-cordon-completed.v1.json re-cordon-completed \
        status "$effect_status" resolution effect-return
      ;;
    ingress_close)
      cats_e3_window_publish_marker 71-ingress-close-completed.v1.json ingress-close-completed \
        status "$effect_status" resolution effect-return
      ;;
    e12)
      cats_e3_window_publish_marker 81-e12-completed.v1.json e12-completed \
        status "$effect_status" resolution effect-return
      ;;
  esac
  publish_status=$?
  if [[ $publish_status -ne 0 ]]; then
    cats_e3_window_error "effect ${slot//_/-} ran with status $effect_status but its completion record could not be persisted; its durable state stays ambiguous"
    cats_e3_window_record_cleanup_error "$effect_status"
    cats_e3_window_record_cleanup_error 125
    return 0
  fi
  printf -v "$state_var" '%s' completed
  printf -v "$status_var" '%s' "$effect_status"
  if [[ $slot == replay && $effect_status -eq 0 ]]; then
    if cats_e3_window_publish_marker \
      40-qualification-terminal-schedulable.v1.json qualification-terminal-schedulable; then
      qualification_transition=terminal_schedulable
    else
      cats_e3_window_record_cleanup_error 125
    fi
    return 0
  fi
  cats_e3_window_record_cleanup_error "$effect_status"
  return 0
}

cats_e3_window_cleanup() {
  cats_e3_window_require_state || return 64
  if [[ $cleanup_completed -eq 1 ]]; then
    return "$cleanup_result_status"
  fi
  [[ $cleanup_in_progress -eq 0 ]] || return 125
  cleanup_in_progress=1
  set +e
  if [[ $qualification_transition == initiated ]]; then
    cats_e3_window_cleanup_slot replay
  fi
  if [[ $qualification_transition == terminal_schedulable ]]; then
    cats_e3_window_cleanup_slot re_cordon
  fi
  if [[ $ingress_open_initiated -eq 1 ]]; then
    cats_e3_window_cleanup_slot ingress_close
  fi
  cats_e3_window_cleanup_slot e12
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
  cats_e3_window_require_state || return 64
  trap 'cats_e3_window_abort $?' EXIT
  trap 'cats_e3_window_handle_signal 130' INT
  trap 'cats_e3_window_handle_signal 143' TERM
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
