# ADR-0004: Use one Rust workspace and layered verification environments

- Status: Accepted
- Date: 2026-07-21

## Context

Cats has shared protocols and correctness invariants across the control plane,
Node agent, Guest agent, block service, adapters, and CLI. Maintaining those
contracts in multiple production languages would duplicate wire types, error
semantics, and test infrastructure. Linux/KVM behavior also cannot be proven by
macOS unit tests alone.

## Decision

1. All production components live in one Rust Cargo workspace.
   - `cmd/` contains executable composition roots and the CLI.
   - domain and protocol crates own provider-neutral contracts.
   - `control-plane`, `node-agent`, `guest-agent`, and `blockd` own their
     respective runtime behavior.
   - provider products remain in adapters and deployment code.
2. Shared wire and persisted types have one Rust definition where component
   boundaries permit it. Compatibility is still tested at serialized and
   process boundaries rather than assumed from shared source.
3. Python and shell are limited to experiments, operational probes, fixtures,
   and correctness oracles. They do not become a second production runtime.
4. Verification has three layers:
   - portable workspace tests and local adapters for fast correctness work;
   - Linux containers for NBD, vhost-user, systemd-facing contracts, and code
     compiled out on macOS;
   - on-demand real KVM, S3, PostgreSQL, and multi-node environments for the
     acceptance boundaries that containers cannot prove.
5. Raw experiment inputs and results record environment, sample count, and
   correctness oracle under `experiments/`. Prototype numbers are not SLAs.

## Consequences

- One toolchain and type system cover the production path.
- Linux-only changes require the Linux quality gate, and Host/VMM claims require
  real-environment evidence proportional to their risk.
- A future language split requires a concrete isolation boundary and a new ADR;
  team size or temporary staffing is not an architectural reason by itself.
