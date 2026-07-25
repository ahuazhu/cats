Durable cloud workspaces

# Your Linux workspace, *ready when you are.*

Cats gives every workspace a real Linux microVM with durable disks and a stable identity. Work at full speed, let it sleep when idle, and wake it without rebuilding your environment.

<a href="/user/" class="button-link primary">Open console →</a> <a href="/docs/getting-started/" class="button-link secondary">Read the quickstart</a>

True pay-as-you-go Durable data by default Linux ready on demand

![](/assets/cats-mark.svg)**dev-workspace**ubuntu-24.04 · 2 CPU · 2 GiB

RUNNING

    $ cats login
    signed in · workspace acme-dev

    $ cats create dev
    creating durable RootDisk…
    starting guest… ready

    $ cats exec dev -- git status
    On branch main
    nothing to commit, working tree clean

    idle → suspended · work preserved

Active**Running**

Fast wake**Suspended**

Local snapshot**Warm**

Zero compute**Cold**

One durable environment

## Keep the machine. Release the compute.

A Cat is a long-lived Linux microVM, not a disposable container session. Its name and disk outlive any one host.

⌁

### A real Linux boundary

Run an independent kernel in KVM, install normal packages, and use an unmodified ext4 filesystem. The Guest never receives platform storage credentials.

↻

### Sleep without starting over

Running, Suspended, Warm, and Cold are distinct states. Fast host-bound resume is available, and every failed fast restore converges to a clean Cold start.

▱

### Disks that survive hosts

Successful FLUSH operations publish to durable remote storage. Local NVMe is a cache, while fencing keeps every PersistentDisk single-writer in V1.

Lifecycle, made explicit

## Four states. No vague “sleep” mode.

Choose the right balance between wake speed, preserved process state, and complete host independence.

1

### Running

vCPU executes, memory is resident, disks keep publishing durable generations, and endpoints can serve traffic.

Full compute

2

### Suspended

vCPUs pause and process state stays on the original host. The VMM and host affinity remain for the shortest resume path.

Process state kept

3

### Warm

The VMM exits after a host-local snapshot. Runtime RSS becomes zero, but restore still uses the original healthy host.

Local snapshot

4

### Cold

All host runtime resources are released. A new host can boot from the last durable disk generation.

Host independent

Durability contract

## Your disk is the truth. The host is replaceable.

Cats keeps the user-facing promise narrow and testable: a successful durable FLUSH survives permanent host loss.

✓

**Standard block devices**

The Guest sees virtio block devices and ordinary ext4—never object-store APIs or metadata credentials.

✓

**Small writes stay small**

The block engine tracks dirty logical chunks. It does not upload an entire sparse virtual disk to commit a small working set.

✓

**Old writers fail closed**

Every attachment has a fencing epoch. A host that returns after a partition cannot publish over a newer writer.

✓

**PersistentDisk is independent**

Destroying a Cat removes its RootDisk; a detached PersistentDisk remains available until you explicitly delete it.

Simple prepaid pricing

## Pay for compute by the hour. Start with $10 on us.

Every new billing account receives a one-time $10 promotional credit. No subscription and no seat fee—add prepaid funds securely with Stripe when you need more.

### CPU — $0.07 / CPU-hour

Charged from cumulative cgroup CPU time with exact integer rating.

### Memory — $0.04375 / GiB-hour

Charged from memory usage integrated over time. One GiB is 2³⁰ bytes.

### New account credit — $10

Applied once per billing account. The console shows near-real-time usage, remaining credit, and Cat-level detail.

Open-period totals are provisional until usage settles. Prices above cover the currently published CPU and memory meters.

## Start with one Cat.

Follow the quickstart, create a durable workspace, run a command, and understand exactly what happens when it sleeps.

<a href="/docs/getting-started/" class="button-link primary">Get started →</a>
