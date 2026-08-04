# Kernel NBD attach mode: why a leaked device is permanent and invisible (2026-08-04)

Measured for issue #79, after 27 of a 64-device pool were found connected to
servers that no longer existed on `metal-1`.

## Environment

| | |
| --- | --- |
| Host | AWS `c5.2xlarge`, Ubuntu 24.04, kernel `6.17.0-1019-aws` |
| Client | `nbd-client` 3.26.1 (the Ubuntu package `install-worker.sh` installs) |
| Pool | `modprobe nbd nbds_max=8` |
| Server | `nbd-server` 3.26.1 for the kernel-behaviour probes; a debug-build `cats-blockd` (sqlite metadata + file object store) for the ones that decide anything |
| Scripts | `probe2.sh` `probe4.sh` `probe5.sh` `probe6.sh` `probe7.sh`, raw output under `raw/` |

Two probes were discarded before these: `nbd-server` forks a child per
connection, so killing the process `pgrep` returns first leaves the connection
alive and every "server killed" observation in that round was of a healthy
device. `probe4.sh` onwards kill every `nbd-server`, and `probe6.sh`/`probe7.sh`
use single-process `cats-blockd` instead.

## What was measured

`nbd-client` defaults to configuring the device over netlink and exiting.
Nothing then stays resident, and `/sys/block/nbdN/pid` names the process that
configured the device and is already gone.

With a real `cats-blockd` behind the device (`raw/probe6.log`):

| | netlink (the default, and what production ran) | ioctl (`-nonetlink`) |
| --- | --- | --- |
| healthy, server alive | `pid=17776` **not alive**, `size=2097152` | `pid=17911` **alive** (`comm=nbd-client`), `size=2097152` |
| server killed, disk held open | `pid=17776` not alive, `size=2097152` | `pid=17911` not alive, `size=2097152` |
| **can a scan tell those apart** | **no — byte for byte identical** | **yes** |
| after the last opener closes | still `size=2097152`: **permanent** | `pid` absent, `size=0`: **released** |
| `nbd-client -d` | rc=0 in 4-5 ms, settles in 200 ms | same |
| device reusable afterwards | yes | yes |

Kill patterns under `-nonetlink`, no opener holding the device
(`raw/probe5.log`): killing the resident `nbd-client`, or it and the server
together, both leave `pid` absent and `size=0` — the device reclaims itself.
With an opener held (`raw/probe5b.log`), both leave the leaked shape, and the
device settles 200 ms after the opener exits.

Two further results worth recording, both contradicting assumptions in the
issue:

- **I/O to a leaked device fails, it does not block.** `dd ... iflag=direct`
  against a device whose server was killed returned
  `Input/output error` immediately in every mode (`raw/probe4.log`). The
  uninterruptible-sleep deadlock reported on `metal-1` is therefore not a
  direct consequence of this state; what is directly demonstrated here is the
  pool exhaustion.
- **Reading `pid` and `size` is safe.** 1-2 ms on leaked devices, no I/O to the
  device itself, so the scan can run on the heartbeat.

## Throughput cost of `-nonetlink`

Same host, same debug `cats-blockd`, file-backed object store on gp3
(`raw/probe6.log`, `raw/probe7.log`):

| | netlink | ioctl |
| --- | --- | --- |
| sequential 256 MiB write, O_DIRECT (2 runs) | 36.0 / 33.4 MB/s | 36.0 / 36.1 MB/s |
| 4 KiB random write, qd32, 25 s (2 runs) | 59.2 / 58.6 MiB/s (15.1k / 15.0k IOPS) | 55.0 / 51.7 MiB/s (14.1k / 13.2k IOPS) |

Sequential is a wash. Random write measured 7-12% lower under ioctl, with both
ioctl runs below both netlink runs — but within-run variance was large (fio
reported stdev ~9k IOPS on a ~14k mean) and this is a debug build against a
local file store, not NVMe and S3. Treat it as a question to put to ADR-0015,
not as a bound on production.

## What it changed

- The attach uses `-nonetlink` (`node-agent/src/ch.rs`). Under netlink a leaked
  device is both permanent and indistinguishable from a healthy one, so no
  detector of any kind can work; under ioctl the usual case reclaims itself and
  the rest is recognizable.
- Every disconnect is guarded on nothing having the device open. On the first
  boot after this change the pool still holds netlink-attached devices whose
  recorded pid is dead while they are healthily serving a Cat, and an open file
  descriptor is the only thing that separates those from a leak.
- `tests/tests/nbd_leak_reclaim.rs` reproduces both shapes against a real
  kernel and is what should be re-run when the kernel or `nbd-client` moves.
