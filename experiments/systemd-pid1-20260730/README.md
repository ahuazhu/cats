# systemd PID 1 lifecycle A/B — 2026-07-30

## Result

A Cat can use systemd as PID 1 and ordinary enabled Linux services behave as
expected across the Cats lifecycle:

- Warm restore preserved the kernel boot ID, the probe service PID, and its
  start count.
- Cold restart produced a new kernel boot ID and restarted the enabled probe
  service exactly once.
- Every formal A/B lifecycle cycle preserved the durable canary.

The measured cost was concentrated in Cold boot. Warm restore itself had no
material regression in this small sample.

| Boundary | Samples | `cats-init` baseline | systemd PID 1 | Delta |
|---|---:|---:|---:|---:|
| First create to Guest Agent health | 1 each | 16.905 s | 18.325 s | +1.420 s (+8.4%) |
| Warm restore only, P50 | 5 each | 0.386 s | 0.379 s | -0.007 s (-1.9%) |
| Warm snapshot + restore, P50 | 5 each | 1.004 s | 0.678 s | -0.325 s (-32.4%) |
| Cold start to Guest Agent health, P50 | 5 each | 10.291 s | 13.314 s | +3.023 s (+29.4%) |
| Cold stop + start, P50 | 5 each | 10.806 s | 13.827 s | +3.022 s (+28.0%) |

The apparent systemd improvements in Suspend and Warm snapshot are not treated
as a product claim. Those phases depend on the run's dirty/RSS working set, and
five samples under background host activity are enough for a directional
comparison, not an SLA.

## Linux service proof

The probe was a normal `Type=simple` unit enabled into
`multi-user.target`, with a persistent start counter:

| Boundary | Cat/restore ready | Service ready | PID | Start count |
|---|---:|---:|---:|---:|
| Initial | 19.758 s | 19.758 s | 359 | 1 |
| Warm restore | 0.434 s | 0.434 s | 359 | 1 |
| Cold restart | 14.237 s | 14.822 s | 302 | 2 |

Warm therefore resumed the same userspace process. Cold performed a fresh boot,
and systemd restarted the enabled service 0.585 s after the Cats Guest Agent
reported healthy.

The stock image also attempted `serial-getty@ttyS0.service`, although this
Cloud Hypervisor configuration records serial output to a Host file and exposes
no Guest `/dev/ttyS0`. The unit timed out after 90 seconds. It did not serialize
the probe service—systemd starts wanted units in parallel—but a Cats systemd
image should mask the unused getty to remove the failed unit and log noise. The
production image change adopted after this experiment does mask that unit.

## Method and scope

- Host: AWS `c5d.metal`, 96 vCPU, Linux `6.17.0-1019-aws`.
- VMM: real KVM + Cloud Hypervisor.
- Cat: 1 vCPU, 512 MiB RAM, ext4 root on the production-default kernel-NBD
  block path.
- Durability: `strict`, with real S3 and PostgreSQL adapters.
- The two images were controlled siblings. The baseline image executed
  `tini -> cats-guest-agent`; the test image executed `/sbin/init`. Their exact
  SHA-256 values and binary hashes are in
  [`raw/environment.txt`](raw/environment.txt).
- Formal distributions used five Suspend, five Warm, and five Cold cycles per
  image. First-create has one observation per image and includes initial golden
  image publication, so it is reported as a sample rather than a percentile.
- Another isolated relaxed-durability soak was active on the 96-vCPU Host
  during the paired run. Observed load was roughly 4–6, with more than 180 GiB
  memory available. This is retained as part of the measurement boundary.

These measurements are experiment results, not a production SLA.

## Durability-tier caveat

Exploratory runs on the in-progress `relaxed` dual-watermark branch were not
usable as a systemd performance comparison: systemd Warm snapshot calls hit the
60-second Cloud Hypervisor API timeout, and the direct-init image hit the seed
binary correctness oracle. Both block paths reproduced the issue. Switching
only to the product-default `strict` durability made the controlled A/B and
service proof pass.

This means the result supports systemd on the validated strict path. It does
not yet establish systemd + the current uncommitted relaxed path; that
combination needs a separate correctness fix/retest.

## Raw evidence

- Baseline: [`summary.json`](raw/baseline/summary.json),
  [`lifecycle.csv`](raw/baseline/lifecycle.csv),
  [`run.log`](raw/baseline/run.log)
- systemd: [`summary.json`](raw/systemd/summary.json),
  [`lifecycle.csv`](raw/systemd/lifecycle.csv),
  [`run.log`](raw/systemd/run.log)
- Service proof: [`systemd-service.csv`](raw/service/systemd-service.csv),
  [`summary.json`](raw/service/summary.json),
  [`run.log`](raw/service/run.log)
- Derived comparison: [`comparison.csv`](comparison.csv)
