---
name: verify-the-probe
description: Calibrate a diagnostic against a known positive before believing a negative or absent result. Use when a command, grep, count, log tail or health check returns nothing, zero, or empty and that result is about to justify a conclusion or a destructive action.
---

# Verify the Probe

A probe that finds nothing tells you one of two things, and it does not tell you
which: the thing is not there, or your probe cannot see it. Acting on the first
reading when the second is true is how a healthy fleet gets diagnosed as dead
and how live data gets deleted.

Every incident this skill exists for had the same shape. The command ran, exited
zero, printed nothing, and the emptiness was read as fact.

## The rule

**Before a negative or zero result justifies a conclusion, make the probe
produce a positive on something you already know is there.**

If it cannot, the probe is not evidence and the question is still open.

## When to apply it

Apply it whenever an empty result is load-bearing:

- it is about to become a claim ("there are no X", "nothing is running", "the
  endpoint does not exist");
- it gates a destructive or irreversible step (delete, terminate, overwrite,
  force-push);
- it contradicts something else you believe, including your own earlier reading.

Skip it for a negative that costs nothing to be wrong about.

## How to calibrate

Pick a control whose answer you already know, and run the same probe against it:

- **Searching a codebase for a symbol.** Before concluding a function does not
  exist, grep for one you know does. A pattern like `delete.*node` silently
  misses `admin_delete_node`; a control catches that instantly. Prefer searching
  for the narrowest distinctive token (`delete_node`) over a composed regex.
- **Looking for a process.** `pgrep NAME` matches `/proc/pid/comm`, truncated to
  15 characters, so a 16-character binary never matches and a busy host looks
  idle. Confirm with `pgrep -af` or `ps -eo args` and eyeball one real line.
- **Reading a log for progress.** Confirm the process actually writes progress
  before treating a static tail as a stall. Many tools are silent by default or
  when not on a TTY, and `--no-progress`-style flags guarantee it. Measure the
  work directly instead: bytes moved, rows done, `/proc/<pid>/io`.
- **Comparing checksums or counts.** Check the operand is non-empty before
  comparing. `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  is the SHA-256 of zero bytes; seeing it means your input was empty, not that
  the data differs. Any "mismatch" against it is a plumbing failure.
- **Timing or throughput.** A rate of zero under a timeout usually means the
  transfer had not completed within the window, not that throughput is zero.
  Re-measure with a longer bound, or against a control host, before calling a
  network dead.
- **Querying an API or table.** Distinguish "returned an empty list" from
  "errored and the error was swallowed". Check the status code and stderr, not
  just the payload.

## Errors that arrive as emptiness

The most dangerous variant: a step fails, its error goes to a discarded stream,
and the next step consumes an empty input and reports a confident wrong answer.

Guard the pipeline, not just the final comparison:

- do not let a failed fetch flow into a checksum, parser or counter;
- in shells, remember `set -e` does not catch a failure mid-pipeline; check
  `PIPESTATUS`, or `set -o pipefail`;
- when a script's last step is a verdict, make it prove its input was real
  before it prints a verdict at all.

## Reporting

When a probe turns out to have lied, say what the probe actually measured, not
just the corrected fact. "`pgrep` matches a 15-character `comm`, so the
16-character name never matched" is reusable. "Actually there were 3 running" is
not, and the next reader repeats the mistake.

If a conclusion you already reported rested on a bad probe, correct it plainly
and say which claims depended on it.
