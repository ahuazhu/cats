One design choice

# Most sandboxes are an action. *A Cat is the machine you come back to.*

That is not a turn of phrase. An action ends and scatters — state becomes a by-product, stopping means discarding, and the bill follows what you requested. A machine you come back to inverts all three. Everything below is a consequence of that one choice, not a feature list.

<a href="/user/" class="button-link primary">Open the console →</a> <a href="/docs/getting-started/" class="button-link secondary">Read the quickstart</a>

State outlives the process The Guest is a real machine You pay for what you used

![](/assets/cats-mark.svg)**dev-workspace**ubuntu-24.04 · 2 CPU · 2 GiB

Running

    $ cats create dev
    Creating persistent RootDisk… ready

    $ cats exec dev -- apt install -y ripgrep
    as root, on unmodified ext4

    work leases reached zero → suspended · process state kept

    $ cats exec dev -- rg TODO src/
    woken · same process, same disk
    src/main.rs:42: // TODO: converge the retry policy

Active**Running**

Process kept**Suspended**

Zero resident**Warm**

Host-free**Cold**

Consequence one

## State has to outlive the process.

If you are going to come back, turning it off cannot mean losing it — the dependencies you installed, the half-finished working tree, the server you left running all have to still be there. That single requirement shapes the whole storage layer: object storage holds the truth, the local disk is only a cache, and the promise has to be testable.

✓

**A successful FLUSH survives permanent Host loss**

A testable promise, not an adjective. It is the oracle for every crash-recovery test we run.

✓

**Local NVMe is a cache you can delete**

Wipe it entirely and the disk still refills chunk by chunk on read, with a byte-identical file tree.

✓

**Only what changed gets committed**

Writing a few files does not upload a whole virtual disk. The engine commits the logical chunks that actually changed.

✓

**A PersistentDisk outlives its Cat**

Change the image, change the shape, delete the Cat — the data stays put and mounts onto the next one. No destroy-and-recreate, no copying files out by hand.

Consequence two

## So it has to be a real machine.

“A container that feels like a VM” holds up in a demo and leaks under real work. We draw the boundary at hardware virtualisation rather than at word choice.

⌁

### Its own kernel, real root

KVM and Cloud Hypervisor, one Linux kernel per Cat. `apt install` just works — no rootless workaround.

▱

### Unmodified ext4

The Guest sees a standard virtio block device, not object storage behind FUSE. So git, SQLite and node\_modules behave exactly as they do on your laptop — atomic rename included.

⊘

### The Guest never holds platform credentials

Object storage, the metadata store and leases are all platform internals. Nothing running inside the Guest can reach them.

Consequence three

## Stopping is not one thing. It is four.

A single vague “sleep” hides three very different trade-offs. We put them on the table: each state says what it keeps, what it releases, and whether it is still tied to the Host it started on.

1

### Running

vCPUs execute, memory is resident, the disk keeps publishing durable generations, and the Endpoint serves traffic.

Full compute

2

### Suspended

vCPUs pause and Guest memory is reclaimed into local backing, with process state kept exactly as it was. Buys the shortest path back.

Process state kept

3

### Warm

A local snapshot lands and the VMM exits: dedicated runtime RSS goes to zero while process state survives. Trades a little wake time for resident memory.

Zero resident, still stateful

4

### Cold

Every Host-local dependency is released; only the remote disk and control-plane record remain. Any healthy Host can bring it back.

No Host affinity

The ladder only descends, and waking always returns to Running. One hard rule holds it together: **any failed fast recovery must converge to a clean Cold boot** — never a stuck intermediate state. Slower is acceptable; not knowing which state you are in is not.

Consequence four

## The platform should not guess whether you are busy.

The industry habit is to infer it from an idle timer, a CPU threshold or network silence. Guess wrong and you either suspend live work or keep paying for an environment nobody is using. We hand that judgement back to your programs.

✓

**No idle timeout, no CPU threshold**

A Cat does not sleep after a quiet interval. It tries to suspend **immediately once no work is known to remain**.

✓

**Work is an explicit, arbitrable signal**

Platform entry points (HTTP, exec, shell) hold a work lease automatically; your own programs can hold one too. Only at zero leases does it sleep.

✓

**The Guest Agent does not decide for you**

It does not scan `/proc`, watch load, or guess at process names. A long-running background job either takes a lease or turns auto-suspend off.

✓

**A request wakes it**

Every Cat gets a stable `*.cats.run` address bound to its name, not to a Host. Traffic arriving there wakes it — you do not have to call an API first.

Consequence five

## Pay for what you used, not what you asked for.

If the bill follows the shape you requested, then “it can sleep” is only marketing — an idle machine still burns money. So the metering basis has to be measured.

◷

### CPU and memory are both measured

CPU from the cgroup's accumulated time, memory from the time integral of `memory.current`. Configure 4 GiB but keep a 1 GiB resident set and you are billed for 1 GiB.

∅

### No per-request charge

There is no invocation line item. A long-lived machine that is accessed occasionally should not get more expensive per visit the rarer those visits are.

◔

### Sleeping costs almost no compute

Warm leaves dedicated runtime RSS at zero. That is what makes “it can sleep” save money instead of just naming a state.

Consequence six

## Prove it is correct before making it fast.

Storage and lifecycle bugs are usually silent — you do not notice them, you discover months later that the data is wrong. So we pin the semantics and leave reproducible evidence first, and optimise the path second.

✓

**Stale writers fail closed**

Every attachment carries a fencing epoch, so a Host that returns after a partition cannot overwrite the current writer. That one has crash-injection tests behind it, not just design intent.

✓

**A different data path, not different semantics**

The block frontend only adapts a protocol. Whichever path a Cat runs on, the commit protocol, dirty tracking, leases and crash recovery are identical, and both share one correctness suite.

✓

**Wake storms queue instead of collapsing**

Concurrent wakes are admitted against a node budget accounted in the memory bytes they must read back. Excess wakes wait rather than being rejected into a full cold boot.

✓

**We publish measurement boundaries**

Every performance number in our docs carries its sample count, hardware and measurement boundary. A prototype measurement never becomes a production promise — you get to judge whether it applies to your workload.

Pricing is the same consequence

## Hourly compute, with $10 to start.

No subscription, no seats, no per-request fee. Every new user's Personal Account receives a one-time $10 credit; top up securely through Stripe when the balance runs low.

CPU

**$0.07**/ CPU-hour

Sampled from accumulated cgroup CPU time and priced in exact integers — not from the core count you requested.

Memory

**$0.045**/ GiB-hour

Billed on the time integral of actual memory use — not the size you configured. One GiB is 2³⁰ bytes.

New account credit

**$10**free to start

Granted once to a new user's Personal Billing Account; creating an Organization or Workspace does not grant it again. The console shows near-real-time usage, balance and per-Cat detail.

<a href="/user/" class="button-link primary">Claim $10 and start →</a>

Amounts are provisional during an open period and settle once usage data is stable. Suspended and Warm remain distinct lifecycle states; the above covers the CPU and memory line items published today.

## Start with one Cat.

Create a persistent workspace, install something, let it sleep for a while, then come back and see whether it is still where you left it.

<a href="/docs/getting-started/" class="button-link primary">Get started →</a>
