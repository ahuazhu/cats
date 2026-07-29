## Start with a Cat — nothing to install

1.  Open the [console](/user/) and sign in with WorkOS. A new user's Personal Account receives a one-time $10 credit.
2.  Click **Create Cat**, pick a shape, confirm. It comes up with a persistent RootDisk attached.
3.  Use **Exec** on the Cat's page to run a command — `uname -a`, or `apt install -y ripgrep`.

That Cat is long-lived from this point on: it suspends itself when idle, wakes when something reaches it, and keeps its disk and its name throughout.

## Install the CLI (optional)

The console is good for creating machines and running one-off commands. Day-to-day work, the `cats shell` interactive terminal and scripting are easier with the CLI.

**The CLI is built from source today**

Prebuilt binaries are coming. Building needs Rust 1.88 or newer, and does not need KVM.

    git clone <your-cats-repository>
    cd cats
    cargo install --path cmd/cats
    cats --help

Working inside the repository, you can also replace `cats` in every example with `cargo run -p cats-cli --bin cats --`.

## Configure access

Users sign in with WorkOS. The CLI uses Device Authorization, opens the verification page in a browser, and stores its short-lived access token and rotating refresh credential only in the operating-system credential store. Cats no longer accepts static user tokens for normal users.

    export CATS_API_URL='https://cats.run'
    cats login
    cats whoami
    cats workspace list
    cats workspace use acme-dev
    cats ls

`cats login` saves the selected control plane and public workspace metadata in a `0600` config file, but never writes tokens there. Use `--workspace acme-prod` or `CATS_WORKSPACE=acme-prod` to override the saved workspace for one command.

**Do not substitute machine credentials**

`CATS_TOKEN` is reserved for administrator/break-glass machine identities. Never use service, object-store, metadata-store, node, or administrator credentials as a normal user login or place them inside a Guest.

## Create your first Cat

    cats create dev \
      --image ubuntu-24.04 \
      --cpus 2 \
      --memory 2GiB \
      --root-size 8GiB

    cats get dev

Creation also creates the RootDisk and enables work-driven auto-suspend by default. Add `--no-auto-suspend` for an always-on background workload that does not use work leases. The CLI waits for the asynchronous Operation by default and prints the resulting Cat; `--no-wait` returns after acceptance, and `--json` selects machine-readable output.

## Run a command

    cats exec dev -- uname -a
    cats exec dev -- sh -lc 'printf "hello\n" > /tmp/hello'

`exec` wakes a Suspended, Warm, or Cold Cat when necessary. Arguments after `--` become the Guest command argv; shell syntax only works when you explicitly invoke a shell as in the second example.

## What the Guest kernel provides

The Guest runs a purpose-built minimal kernel: virtio block, network and vsock, ext4 — and no loadable modules (`/lib/modules` is empty, there is no `modprobe`). Two absences surprise ordinary Linux software:

- **no overlayfs** — container runtimes cannot use their default `overlay2`/`fuse-overlayfs` storage driver;
- **no nf_tables** — `iptables` fails with `Failed to initialize nft: Protocol not supported`, so nothing can create NAT or filter chains.

Both are avoidable rather than fatal. A container runtime works inside a Cat when it stops relying on either:

    dockerd --storage-driver=vfs --iptables=false --ip6tables=false --bridge=none
    docker run --network host ...

With host networking the containers share the Cat's own network namespace: they reach each other over `127.0.0.1` instead of the runtime's DNS, and a container listening on `0.0.0.0:8080` is served by the Cat's endpoint with no port publishing. `vfs` copies each image layer instead of stacking it, so size the RootDisk for the images you load.

Loopback itself is configured: `lo` is up with `127.0.0.1/8`, so localhost between processes works normally.

## Manage work-driven auto-suspend

    cats sleep on dev
    cats sleep status dev
    cats sleep off dev

New Cats start with auto-suspend on. It does not guess from CPU or process lists: the Cat becomes eligible when platform work and fresh Guest work leases are both empty. Applications with continuing background work must use the [Guest Runtime API](/docs/runtime-api/) or run `cats sleep off dev`.

## Stop and start

    cats suspend dev    # host-bound, preserve process state
    cats resume dev
    cats stop dev       # Cold: release compute and host affinity
    cats start dev      # boot from the durable RootDisk

## Clean up

    cats destroy dev

Destroy deletes the Cat and its RootDisk after the operation completes. Independent PersistentDisks survive and require their own `cats disk delete`.

**Destructive**

Snapshot or copy anything you need before destroy. There is no undelete command in the V1 CLI.
