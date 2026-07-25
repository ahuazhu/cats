## Global options

| Option / environment | Default | Purpose |
|----|----|----|
| `--api-url` / `CATS_API_URL` | saved login target, otherwise `https://cats.run` | Control-plane base URL |
| `--workspace` / `CATS_WORKSPACE` | saved Workspace | Override one command without changing the default; `--project` is a compatibility alias |
| `--token` / `CATS_TOKEN` | none | Machine/administrator Bearer credential only; normal users run `cats login` |
| `--no-wait` | off | Return after an Operation is accepted |
| `--json` | off | Print machine-readable JSON where supported |

Global options may appear before or after the subcommand. Use `cats --help` and `cats <command> --help` as the version-authoritative reference.

## Identity and Workspace commands

    cats login
    cats whoami
    cats workspace list
    cats workspace use ACCOUNT/WORKSPACE
    cats --workspace ACCOUNT/WORKSPACE ls
    cats logout

`login` uses WorkOS Device Authorization and stores access/refresh material only in the operating-system credential store. Active WorkOS Organization memberships expose Personal and Organization Accounts and their Workspaces. `workspace use` changes the saved default; `--workspace` affects one command only. A same-Account switch is local, while a cross-Account switch rotates the WorkOS refresh token under a cross-process credential lock. `logout` attempts remote revocation and always removes the local credential.

## Cat commands

    cats create NAME [--image IMAGE] [--cpus N] [--memory SIZE]
                     [--root-size SIZE] [--disk NAME]
                     [--disk-size SIZE] [--mount-at PATH] [--no-auto-suspend]
    cats ls
    cats get NAME
    cats start NAME
    cats stop NAME
    cats suspend NAME
    cats resume NAME
    cats warm NAME
    cats destroy NAME
    cats exec NAME -- COMMAND [ARG...]

`create` defaults to image `ubuntu-24.04`, 2 CPUs, 2 GiB memory, a 1 GiB RootDisk, and auto-suspend enabled. Sizes accept `KiB`, `MiB`, `GiB`, or raw bytes.

## Auto-suspend commands

    cats sleep on NAME
    cats sleep off NAME
    cats sleep status NAME

Status reports platform and Guest work leases, signal freshness, eligibility, and the current reason.

## Disk commands

    cats disk create NAME --size SIZE
    cats disk ls
    cats disk get NAME
    cats disk resize NAME --size SIZE
    cats disk snapshot NAME
    cats disk delete NAME
    cats mount DISK --cat CAT [--at /data]
    cats unmount DISK

## Endpoint commands

    cats expose CAT PORT [--name web] [--protocol http] [--no-wake]
    cats endpoint ls CAT

Every Cat already has a `web` Endpoint for port 8080. `cats expose CAT PORT` reconfigures it; use another `--name` to add a URL.

## Operation commands

    cats operation ls
    cats operation get ID
    cats operation wait ID

Mutations normally wait up to 120 seconds. With `--no-wait`, save the returned ID and use `operation wait` or `operation get`. Safe retries should use the same resource intent; the API attaches idempotency keys to mutations.

## Automation guidance

- Use `--json` instead of scraping aligned human output.
- Treat non-zero exit status as failure. `exec` also fails when the Guest command exits non-zero.
- Do not parse resource IDs, work lease IDs, or Operation IDs for meaning.
- Use WorkOS login for users. Do not log token values or substitute service/administrator credentials for a user session.
