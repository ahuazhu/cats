---
name: rust-pr-review
description: Review a Cats Rust pull request or branch for concrete merge risks, with emphasis on correctness, data safety, concurrency, authorization, compatibility, and missing tests. Use when asked to review a PR, branch, commit range, or Rust diff. Keep the review read-only unless fixes are explicitly requested.
---

# Rust PR Review

Review the change as a correctness gate, not as a style preference exercise.

## Establish the change

1. Read the applicable `AGENTS.md` files, the original task or PR description, and governing ADRs.
2. Determine the intended base and inspect the complete diff from the merge base. Read surrounding code and relevant call sites rather than reviewing isolated hunks.
3. Check `git status` so local, unrelated changes are not mistaken for PR content.
4. Keep the review read-only. Do not edit files, commit, push, approve, or submit comments unless the user explicitly requests those actions.

If the base, task intent, or generated-file status is uncertain, state the assumption in the review.

## Review by risk

Prioritize:

1. data corruption, durability regressions, stale-writer publication, fencing gaps, and unrecoverable lifecycle states;
2. cross-workspace authorization, session-scope, secret exposure, and untrusted-input problems;
3. races, deadlocks, blocking work in async paths, cancellation leaks, shutdown hangs, and unbounded resource growth;
4. incorrect errors, lossy conversions, partial updates, compatibility breaks, and accidental public-API changes;
5. missing tests for changed behavior, failure paths, crash windows, adapter contracts, or Linux-only code;
6. maintainability problems only when the diff introduces a concrete future error or makes an invariant unverifiable.

Apply the Cats invariants: standard virtio block devices and no Guest storage credentials; strict durable FLUSH survives Host loss; relaxed durability has distinct local and remote watermarks; no whole sparse-disk uploads for small writes; PersistentDisk is RWO with one publishing epoch; Workspace is the only owner; Running, Suspended, Warm, and Cold are distinct; failed host-bound restore converges to Cold.

Do not report formatting or Clippy issues that the repository gates already catch unless the gate itself was weakened. Do not demand large redesigns when a focused correction is sufficient. Verify an alleged issue against tests and call sites before reporting it.

## Validate and report

Run focused checks when they materially increase confidence. Use `./scripts/quality.sh fast` for repository gates, `./scripts/quality.sh full` for an exhaustive local result, and `./scripts/quality.sh linux` for Linux-only paths when needed. Never claim a command passed unless it was run.

List findings first, ordered by severity. Each finding must include:

- severity (`P0` through `P3`) and confidence;
- an exact file and line in the changed code;
- a concrete trigger and impact;
- the minimal correction;
- the test that would prevent recurrence.

Keep summaries brief. If no actionable findings remain, say that explicitly and describe only meaningful residual risks or validation gaps.
