## Prerequisites

For this source distribution you need Rust 1.88 or newer and access to a running Cats control plane. Building the CLI does not require KVM; running the full Cloud Hypervisor data path requires Linux x86_64, root privileges, and `/dev/kvm`.

## Build the CLI

    git clone <your-cats-repository>
    cd cats
    cargo install --path cmd/cats
    cats --help

You can also replace `cats` in every example with `cargo run -p cats-cli --bin cats --` while developing in the repository.

## Configure access

Users sign in with WorkOS. The CLI uses Device Authorization, opens the verification page in a browser, and stores its short-lived access token and rotating refresh credential only in the operating-system credential store. Cats no longer accepts static project tokens for normal users.

    export CATS_API_URL='http://127.0.0.1:7300'
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
