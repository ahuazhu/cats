## Global options

| Option / environment | Default | Purpose |
|----|----|----|
| `--api-url` / `CATS_API_URL` | saved login target, otherwise `https://cats.run` | Control-plane base URL |
| `--workspace` / `CATS_WORKSPACE` | saved Workspace | Override one command without changing the default; accepts `workspace`, `account/workspace`, or a workspace ID |
| `--token` / `CATS_TOKEN` | none | Machine/administrator Bearer credential only; normal users run `cats login` |
| `--no-wait` | off | Return after an Operation is accepted |
| `--json` | off | Print machine-readable JSON where supported |

Global options may appear before or after the subcommand. Use `cats --help` and `cats <command> --help` as the version-authoritative reference.

## Identity and Workspace commands

    cats login
    cats whoami
    cats workspace list
    cats workspace create SLUG [--display-name NAME]
    cats workspace use ACCOUNT/WORKSPACE
    cats --workspace ACCOUNT/WORKSPACE ls
    cats logout

`login` uses WorkOS Device Authorization and stores access/refresh material only in the operating-system credential store. Active WorkOS Organization memberships expose Personal and Organization Accounts and their Workspaces. `workspace create` adds an isolated Workspace to the selected Account and requires account-management permission. `workspace use` changes the saved default; `--workspace` affects one command only. A same-Account switch is local, while a cross-Account switch rotates the WorkOS refresh token under a cross-process credential lock. `logout` attempts remote revocation and always removes the local credential.

## Automation tokens

    cats token create LABEL
    cats token list
    cats token revoke ID

A Workspace token is a revocable machine credential for CI. It can manage resources only in the Workspace that issued it, cannot enumerate another Workspace, and cannot create or revoke tokens. The secret is shown once; store it in the CI secret manager and pass it as `CATS_TOKEN` together with the immutable Workspace ID in `CATS_WORKSPACE`.

## Cat commands

    cats create NAME [--image IMAGE] [--cpus N] [--memory SIZE]
                     [--root-size SIZE] [--disk NAME]
                     [--disk-size SIZE] [--mount-at PATH] [--no-auto-suspend]
                     [--expires-in SECONDS]
    cats ls
    cats get NAME
    cats start NAME
    cats stop NAME
    cats suspend NAME
    cats resume NAME
    cats warm NAME
    cats destroy NAME
    cats expiry NAME [--in SECONDS | --at UNIX | --never]
    cats exec NAME [--timeout SECONDS] [--env-file PATH]
                   [--stdin-file PATH] -- COMMAND [ARG...]
    cats deploy CAT APP --image REGISTRY/REPOSITORY@sha256:DIGEST
                    [--env-file PATH]
                    [--registry-username USER --registry-password-stdin]
                    [-- COMMAND [ARG...]]

`create` defaults to image `ubuntu-24.04`, 2 CPUs, 2 GiB memory, a 1 GiB RootDisk, and auto-suspend enabled. Sizes accept `KiB`, `MiB`, `GiB`, or raw bytes.

`exec --env-file` accepts newline-delimited `NAME=VALUE` entries and adds them only to the Guest child process. `--stdin-file` sends arbitrary file bytes to standard input. These options let automation transfer a bootstrap script and runtime credentials without putting either in the command line; do not print secret-bearing files or command environments.

`deploy` pulls OCI/Docker manifests and layers inside the Cat, verifies every `sha256` descriptor, flattens the layers onto the RootDisk, and runs the image under systemd. It uses neither Docker nor OverlayFS. The image must be digest-pinned; tags are rejected. Registry passwords are read from stdin and are not persisted. `deploy --env-file` is different from `exec --env-file`: it becomes persistent systemd configuration on the RootDisk so the service survives Cold boot, and must not contain secrets.

## Auto-suspend commands

    cats sleep on NAME
    cats sleep off NAME
    cats sleep status NAME

Status reports platform and Guest work leases, signal freshness, eligibility, and the current reason.

## Disk commands

    cats disk create NAME --size SIZE
    cats disk ls
    cats disk get NAME
    cats disk snapshot NAME
    cats disk delete NAME
    cats mount DISK --cat CAT [--at /data]
    cats unmount DISK

## Endpoint commands

    cats expose CAT PORT [--name web] [--protocol http] [--no-wake]
    cats endpoint ls CAT

Every Cat already has a `web` Endpoint for port 8080. `cats expose CAT PORT` reconfigures it; use another `--name` to add a URL.

## Operation commands

    cats operation get ID
    cats operation wait ID

Cat create returns an accepted Operation ID. `operation get` reads that exact Operation in the selected Workspace; `operation wait` polls it for up to 120 seconds and exits unsuccessfully for `failed` or `superseded`. Both commands use the strict Runtime Reconciliation decoder.

`operation ls` remains unavailable and sends no HTTP request: the runtime authority deliberately exposes no unbounded Operation list. The old global Operation URL is retired.

## Automation guidance

- Use `--json` instead of scraping aligned human output.
- Treat non-zero exit status as failure. `exec` also fails when the Guest command exits non-zero.
- Do not parse resource IDs, work lease IDs, or Operation IDs for meaning.
- Use WorkOS login for users and a Workspace token for CI. Do not log token values or substitute service/administrator credentials for either scope.
