---
name: rust-smell-audit
description: Audit Cats Rust code for concrete correctness, concurrency, error-handling, test, and maintainability risks. Use when asked for a code-smell audit, technical-debt assessment, Rust quality review, or a prioritized cleanup plan. Keep the audit read-only unless the user separately asks to implement fixes.
---

# Rust Smell Audit

Produce a small, evidence-backed set of actionable findings. Prefer one proven risk over a long list of generic Rust advice.

## Establish the audit boundary

1. Read the applicable `AGENTS.md` files and the ADRs or architecture documents governing the code in scope.
2. Inspect `git status`, the requested files, and any relevant diff or merge base. Preserve unrelated work.
3. Treat an audit request as read-only. Do not edit files, create commits, push branches, or open pull requests unless the user explicitly asks for those actions.
4. State whether the audit covers a diff, a subsystem, or the whole workspace. Call out platform-specific code that was not compiled or exercised.

## Gather evidence

Run the narrowest useful checks first. Use `./scripts/quality.sh fast` for the repository-wide formatting, skill-contract, and Clippy gates. Use focused tests while investigating; use `./scripts/quality.sh full` only when a full workspace result is useful. Run `./scripts/quality.sh linux` when the audited change touches Linux-only vhost-user-blk or node-agent paths and no native Linux host is available.

Inspect call sites and tests before labeling a pattern as a defect. In particular, do not report every `unwrap`, `clone`, lock, large function, or string comparison mechanically. Demonstrate a reachable failure mode, maintenance cost, or missing invariant.

Prioritize:

- data loss, stale-writer publication, fencing, durability-watermark, and crash-recovery failures;
- cross-workspace authorization or credential-boundary violations;
- lifecycle drift between Running, Suspended, Warm, and Cold, including missing Cold fallback;
- locks held across blocking work or `.await`, races, deadlocks, cancellation leaks, and shutdown hangs;
- swallowed errors, panic paths reachable from untrusted input, lossy numeric conversions, and partial-state updates;
- public APIs that expose representation accidentally or make invalid states easy to construct;
- unnecessary ownership complexity such as unexplained `Arc<Mutex<_>>`, cloning large buffers, or node-wide serialization;
- duplicated protocol constants, stringly typed state, oversized modules, and abstractions with only one fake implementation;
- missing regression, crash-injection, authorization, adapter-contract, or Linux `cfg` coverage.

Preserve Cats invariants. The Guest never receives storage credentials; strict durable FLUSH survives permanent Host loss; relaxed durability keeps local and remote watermarks distinct; small dirty sets never upload a whole sparse disk; PersistentDisk is RWO with exactly one publishing epoch; Workspace is the sole resource owner; Suspended and Warm remain distinct host-bound states.

## Report findings

Return at most ten findings, ordered by impact. For each finding include:

- severity (`P0` through `P3`) and confidence;
- an exact file and line;
- the triggering scenario and user-visible or operational impact;
- the evidence that makes the issue concrete;
- the smallest safe correction;
- the regression test or validation that would prove the correction.

Separate confirmed findings from open questions. Do not inflate severity to make stylistic cleanup sound urgent. If no actionable issue is found, say so directly and list the important residual test or platform gaps.

End with a staged cleanup plan only when findings exist: correctness and safety first, then simplification, then optional polish. Keep unrelated dependency upgrades and broad rewrites out of that plan.
