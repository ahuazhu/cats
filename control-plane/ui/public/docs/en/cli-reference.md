## Global options

| Option / environment | Purpose |
|----|----|
| `--api-url` / `CATS_API_URL` | Control-plane base URL |
| `--workspace` / `CATS_WORKSPACE` | Select one immutable Workspace for this command |
| `--token` / `CATS_TOKEN` | Machine or administrator credential |
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

    cats create NAME --boot-image-digest sha256:DIGEST
                     [--cpus N] [--memory SIZE]
                     [--root-size SIZE]
                     [--durability strict|relaxed]
    cats ls
    cats get CAT_ID

`create` requires one digest-pinned boot image. It defaults to 2 CPUs, 2 GiB memory, a 1 GiB RootDisk, and Strict durability. List follows bounded cursors; item lookup accepts only immutable `cat_…` IDs.

## Current PersistentDisk commands

    cats disk create NAME --size SIZE [--durability strict|relaxed]
    cats disk ls
    cats disk get DISK_ID

The create request is persisted before transport. An ambiguous retry of the same command reuses the exact path, body, and Idempotency-Key. Capacity is immutable in this release. Disk item lookup accepts only immutable `disk_…` IDs.

## Operation commands

    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

Cat create returns an Operation ID. Both commands use the exact Workspace-scoped Operation lookup; there is no Operation list.

## Cutover boundary

Lifecycle, Guest command, deployment, Endpoint, Cat delete, and PersistentDisk mutation commands are absent from shipped help. Compatibility parsing, where retained, fails before constructing an HTTP client and never probes a legacy route.
