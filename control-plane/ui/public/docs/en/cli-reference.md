## Global options

| Option / environment | Purpose |
|----|----|
| `--api-url` / `CATS_API_URL` | Control-plane base URL |
| `--workspace` / `CATS_WORKSPACE` | Select one immutable Workspace for this command |
| `--token` / `CATS_TOKEN` | Machine or administrator credential |
| `--no-wait` | Print the accepted Operation ID without waiting for settlement |
| `--json` | Print machine-readable output where supported |

`cats --help` and `cats <command> --help` are version-authoritative.

## Identity and Workspace

    cats login
    cats logout
    cats whoami
    cats workspace list
    cats workspace create SLUG [--display-name NAME]
    cats workspace use ACCOUNT/WORKSPACE
    cats token create LABEL
    cats token list
    cats token revoke ID

## Current Cat commands

    cats create NAME [--cpus N] [--memory SIZE]
                     [--root-size SIZE]
                     [--durability strict|relaxed]
    cats ls
    cats get CAT_ID
    cats run CAT_ID
    cats suspend CAT_ID
    cats warm CAT_ID
    cats cold CAT_ID
    cats destroy CAT_ID

`create` automatically uses the deployment's current qualified boot image. It defaults to 2 CPUs, 2 GiB memory, a 1 GiB RootDisk, and Strict durability. List follows bounded cursors; item lookup accepts only immutable `cat_…` IDs.

The five lifecycle commands for an existing Cat also require an immutable `cat_…` ID. The CLI persists the exact empty request and Idempotency-Key before sending it, and replays both after an ambiguous response. By default it waits on the returned Operation; `--no-wait` prints the Operation ID immediately. The retired `start`, `stop`, `delete`, and `resume` commands are not compatibility aliases.

## Current PersistentDisk commands

    cats disk create NAME --size SIZE [--durability strict|relaxed]
    cats disk ls
    cats disk get DISK_ID
    cats disk attach DISK_ID --cat CAT_ID --mount-path /absolute/guest/path
    cats disk detach DISK_ID --cat CAT_ID --mount-path /absolute/guest/path
    cats disk snapshot create DISK_SLUG SNAPSHOT_SLUG
    cats disk snapshot list [--disk DISK_SLUG]
    cats disk snapshot show SNAPSHOT_SLUG
    cats disk snapshot restore SNAPSHOT_SLUG
    cats disk snapshot destroy SNAPSHOT_SLUG

Create, attach, and detach requests are persisted before transport. An ambiguous retry of the same command reuses the exact path, body, and Idempotency-Key. Capacity is immutable in this release. Disk item lookup accepts only immutable `disk_…` IDs; binding mutations require a terminal Cold Cat and an exact absolute Guest path.

Snapshot create uses both user-selected slugs as its stable semantic identity.
Create and restore require a remotely durable, unowned disk and a stable Cold
Cat when the disk is attached. Restore first reads the latest disk generation
and sends it as an optimistic precondition; a concurrent disk change fails
instead of restoring over an unseen head. Destroy removes the restore point and
its GC protection, not the PersistentDisk.

## Operation commands

    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

Cat create and the five lifecycle commands return an Operation ID. Both Operation commands use the exact Workspace-scoped product lookup; there is no Operation list and no Node execution payload.

## Cutover boundary

Endpoint and capacity mutation commands are absent from shipped help. Retired lifecycle aliases are not parsed and never probe a legacy route.
