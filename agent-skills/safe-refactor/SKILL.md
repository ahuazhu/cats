---
name: safe-refactor
description: Refactor Cats Rust code while preserving observable behavior, storage and protocol compatibility, lifecycle semantics, and operational invariants. Use when asked to simplify, extract, split, rename, remove duplication, or pay down a confirmed code smell without adding a feature.
---

# Safe Refactor

Make one coherent simplification at a time and prove that behavior did not change.

## Define the behavior boundary

1. Read the applicable `AGENTS.md` files and governing ADRs before editing.
2. Inspect `git status` and the current diff. Preserve unrelated work; use a separate worktree when the user requests one or when isolation is necessary.
3. Describe the exact smell and the behavior that must remain stable. Include public APIs, serialized formats, CLI output, HTTP semantics, metrics, error classes, and timing or ordering guarantees when relevant.
4. Find existing tests that characterize that behavior. Add a focused characterization or regression test before structural changes when the behavior is not already pinned down.

Do not call a feature change a refactor. Stop and ask for direction if the cleanup requires changing a public contract, accepted ADR, persistent format, durability semantics, or lifecycle transition.

## Refactor in a narrow seam

- Prefer moving existing behavior behind a clear name over introducing speculative layers.
- Keep provider-neutral contracts in `cats-storage` and concrete product adapters under `adapters/`.
- Keep ownership and synchronization no broader than required. Explain any new `Arc`, mutex, channel, task, or thread.
- Preserve error context and fail-closed behavior. Do not replace a typed error with a panic or silently ignore cleanup failures.
- Avoid unrelated formatting, dependency upgrades, renames, and opportunistic cleanup.
- Keep Linux-only vhost-user-blk and node-agent code behind the existing platform gates.

Preserve Cats invariants: no Guest storage credentials; strict durable FLUSH survives Host loss; relaxed local and remote watermarks remain distinct; small writes do not upload sparse disks; stale attachment epochs cannot publish; Workspace is the sole owner; Suspended and Warm stay distinct and fall back cleanly to Cold; RootDisk and PersistentDisk lifecycles remain independent.

## Validate continuously

Run focused tests after each meaningful edit. Inspect the resulting diff for accidental behavior changes, expanded visibility, changed wire or disk formats, and lost error context.

Use:

- `./scripts/quality.sh fast` during iteration;
- `./scripts/quality.sh full` before handoff;
- `./scripts/quality.sh linux` when Linux-only paths changed and the current host is not Linux.

The build must precede the full workspace test run because integration tests build helper binaries.

## Hand off

Summarize the smell removed, the behavior boundary preserved, and any API or file moves. Report the exact checks run and their outcomes. Mention residual risks or untested platform paths plainly. Do not claim the change is behavior-preserving solely because it compiles.
