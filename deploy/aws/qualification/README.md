# Issue #124 temporary worker qualification

This directory is the audited lifecycle for one disposable bare-metal worker
used by issue #124. It does not make the worker a Terraform fleet member and
it never clones a production worker. The fixed AMI, private subnet, security
group and existing worker instance profile are reused read-only. The instance
gets a new EC2 identity, a new `q124-<run>-<sha>` node identity, a fresh
encrypted/deletable root volume and an explicitly confirmed EC2 NVMe instance
store cache. No source user-data, instance identity, database credential,
volume or `/var/lib/cats` state is copied.

The workflow is deliberately disabled until the platform stack has created
the dedicated role. Set `github_qualification_worker_enabled=true` and feed the
existing worker artifact bucket ARN to
`github_qualification_artifact_bucket_arn`. Apply that reviewed Terraform
change separately. The resulting `github_qualification_worker_role_arn` is the
only value accepted as repository variable `Q124_AWS_ROLE_ARN`; do not widen
the ordinary release role.

## Fixed repository variables

The dispatcher exposes no account, cluster, workspace, source node or launch
scope as user input. Configure these repository variables from reviewed stack
outputs and the one selected healthy source worker:

| Variable | Authority |
| --- | --- |
| `AWS_REGION`, `EKS_CLUSTER_NAME`, `AWS_ROLE_ARN` | existing production deployment variables |
| `Q124_AWS_ROLE_ARN`, `Q124_ACCOUNT_ID` | platform qualification output / production account |
| `Q124_WORKSPACE_ID`, `Q124_CONTROL_URL` | dedicated qualification workspace / production endpoint |
| `Q124_SOURCE_INSTANCE_ID`, `Q124_SOURCE_NODE_ID` | one known-positive worker, probes only |
| `Q124_WORKER_AMI_ID`, `Q124_WORKER_INSTANCE_TYPE` | platform `metal_worker_ami` / type |
| `Q124_WORKER_SUBNET_ID`, `Q124_WORKER_SECURITY_GROUP_ID` | platform private subnet 0 / worker SG |
| `Q124_WORKER_INSTANCE_PROFILE` | platform worker instance profile |
| `Q124_WORKER_ARTIFACT_BUCKET` | existing infrastructure worker artifact bucket |
| `Q124_WORKER_CACHE_DEVICE` | exact EC2 NVMe instance-store device, normally `/dev/nvme1n1` after operator verification |
| `Q124_CHUNKSTORE_BUCKET`, `Q124_RUNTIME_SECRET_ARN` | existing worker deployment values |
| `RDS_MASTER_USER_SECRET_ARN`, `Q124_DB_NAME` | platform database outputs |

At the time this tool was authored, the repository had only the ordinary
release variables (`AWS_REGION`, `AWS_ROLE_ARN`, `ECR_REPOSITORY`,
`EKS_CLUSTER_NAME`, `PRODUCTION_TFVARS_B64`, `RDS_MASTER_USER_SECRET_ARN`,
`TF_STATE_APPLICATION_KEY`, `TF_STATE_BUCKET`). Therefore the workflow must
fail closed until every `Q124_*` value above is deliberately installed. No
live qualification has been run by this change.

`Q124_WORKER_SECURITY_GROUP_ID` is singular by contract. Both the read-only
source template and the new instance must have exactly that one group; an
additional group is a hard failure, not an implicitly trusted extension.

## Lifecycle and confirmations

Run `.github/workflows/qualify-temporary-worker.yml` only from `main`. Its
single concurrency group prevents overlapping lifecycle transitions.

1. `provision`: confirmation `PROVISION_Q124_TEMP_WORKER`, TTL 1–24 hours.
   It archives the exact main SHA, uploads only
   `worker/qualification-124/<sha>/...`, launches with `RunInstances` (never a
   source instance id or launch template), verifies SSM, IAM, KVM, NBD, agent,
   credential refresher, S3, PostgreSQL, heartbeat and 1 CPU/1024 MiB capacity.
   The first observed registration must be empty `cordoned`.
2. `validate`: confirmation `VALIDATE_Q124_<first-12-manifest-hash>`.
3. `drain`: confirmation `DRAIN_Q124_<first-12-manifest-hash>`. Every assigned
   Cat must belong to the fixed workspace and have a `q124-` name. The control
   assignment set must equal the local runtime-ledger set before the drain.
   Completion requires `cordoned`, zero assignments, zero reported orphans,
   zero runtime records/processes and zero pending packs.
4. `withdraw`: confirmation `WITHDRAW_Q124_<first-12-manifest-hash>`. It repeats
   the idle proof, stops the worker, and uses the supported exact node DELETE.
5. `return`: confirmation `RETURN_Q124_<instance-id>_<node-id>`. Only after the
   calibrated node-absence and idle proofs does it disable termination
   protection and terminate the exact manifest instance. It waits for EC2
   termination, SSM absence and control-plane absence.

The manifest is canonical JSON stored as a workflow artifact and in issue #124
with its SHA-256 marker. It contains identifiers, launch inputs, source/archive
digests and timestamps, but no admin token, database password, runtime token or
AWS credential. Later transitions require the unique issue comment and exact
canonical digest.

The manifest's 1–24 hour interval is parsed and checked. `validate` refuses an
expired worker; drain/withdraw/return deliberately remain available after
expiry so TTL enforcement cannot prevent safe cleanup. The provisioned source
SHA and GitHub run id must match the live instance's `CatsSourceSha` and
`CatsRunId` tags. They are not required to equal a later cleanup run's main SHA:
main may advance while the worker exists, and binding cleanup to the new SHA
would strand it. The exact archive key binds the source SHA and bundle digest.

Failure and cancellation traps are intentionally narrower than normal cleanup:
they can act only on the exact instance id returned to the current invocation
after its issue/purpose/node tags are re-read. If the node has any assigned or
orphan Cat, runtime record, pending pack, or ambiguous response, cleanup stops
without terminating. No wildcard/tag-selector mutation, shared security-group,
RDS, S3 policy, DNS, Terraform-state, data-volume or production-Cat deletion is
implemented.

## Local contract gate

Run:

```bash
deploy/aws/qualification/tests/contracts.sh
```

The stateful doubles exercise wrong account/workspace/source/manifest digest,
partial scope, non-empty nodes, duplicate provisioning, cancellation, partial
failure cleanup order, idempotent retries, tag mismatch and exact positive
termination. These tests are local evidence only; they are not a live PASS.

## Permissions and intentionally unexecuted work

The qualification role can describe EC2/SSM inventory, launch only the fixed
AMI/subnet/SG/type with required issue tags, pass only the worker role to EC2,
send only `AWS-RunShellScript` to tagged qualification instances, read/write
only the qualification artifact prefix, and modify/terminate only tagged
qualification instances. It has no permission to delete S3 objects or volumes,
change shared networking/database/DNS resources, or read runtime/database
secrets (the existing EC2 worker role does that from the host).

`RunInstances` has no IAM instance-profile resource type. The policy therefore
uses both mechanisms AWS exposes: exact-role `iam:PassRole` with
`iam:PassedToService=ec2.amazonaws.com`, plus an `ec2:InstanceProfile` ARN
condition on `RunInstances` for the exact existing profile. After the release
identity reads the admin token, the workflow overwrites its AWS environment
with the qualification session. The token stays in a mode-0600 runner-temp
file, is masked, and an `always()` finalizer truncates and unlinks that exact
file (plus the exact staging files); the hosted runner itself is ephemeral.

This repository change performs no Terraform apply, repository-variable write,
workflow dispatch, EC2/SSM call, node mutation, production test, drain or
termination. Those remain explicitly unexecuted until this draft is reviewed,
merged to main, the dedicated role is applied, and an operator supplies the
exact confirmation.
