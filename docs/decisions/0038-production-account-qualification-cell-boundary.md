# ADR-0038: Production-account qualification cell has an isolated Terraform authority boundary

- Status: Accepted
- Date: 2026-08-06
- Relates to: ADR-0012 (Terraform-managed AWS resources), ADR-0024
  (digest-pinned delivery), ADR-0036 (RC source chain); issues #211 and #241

## Context

Architecture V2 needs a permanent, production-shaped qualification environment.
The project owner authorized building it in AWS account `869621413820`, region
`us-east-1`, because reaching the target shape quickly matters more than cost.
That authorization does not turn existing production infrastructure into test
infrastructure. The account already contains production VPC, EKS, RDS, EC2,
S3, DNS, IAM and data resources. Reusing any of them would let a qualification
fault, teardown or candidate build affect production and would make a passing
result depend on undeclared state.

The difficult boundary is therefore not the AWS account. It is the authority
to select and mutate resources inside that account. Terraform review alone is
insufficient: a configuration can import an existing object, use a data source
as hidden authority, or save a plan whose concrete IDs differ from the names a
reviewer expected.

## Decision

### The cell is a new resource lineage

The canonical namespace is `cats-qualification-v2`. Every resource created for
the cell is Terraform-owned, has a name derived from that namespace, and, when
the AWS resource is taggable, carries the exact identity tags:

```text
Project=Cats
Environment=qualification
QualificationNamespace=cats-qualification-v2
QualificationCell=<declared cell id>
ManagedBy=terraform
```

The AWS account and region are inputs, not source-code credentials. The
provider uses `allowed_account_ids`, and Terraform checks the caller identity,
region, namespace, cell id and bootstrap principal before planning a resource.
The production account ID must be supplied explicitly by the reviewed
invocation. It is intentionally not a default hidden in the module.

Existing VPCs, subnets, route tables, security groups, EKS clusters, RDS
instances/proxies, EC2 instances, buckets, KMS keys, hosted zones, records,
certificates, OIDC providers, instance profiles, roles, data or credentials
are not inputs to the qualification cell. G1 creates replacements inside the
cell. There are no Terraform imports and no `data` lookups for production
runtime resources.

### Bootstrap authority is the only account-level exception

An explicitly named bootstrap principal may create the boundary after saved
plan review. It is an account-level operator and is not a qualification actor.
The G0 bootstrap creates only:

- a qualification-only KMS key and alias for Terraform state;
- a qualification-only, versioned and private S3 state bucket using that key;
- a state role trusted by the exact bootstrap principal and authorized only
  for that bucket and key.

The state role can read/write state and the S3 native lock object. It cannot
list or inspect production infrastructure and cannot create AWS runtime
resources. G1 must introduce service-specific plan/apply roles behind a
separate reviewed policy; attaching account-wide `ReadOnlyAccess` or
`AdministratorAccess` is forbidden. This prevents a convenient planning role
from becoming a cross-production discovery credential.

Bootstrap state is local because it creates its own backend. It must be stored
in an approved encrypted operator vault. Every later qualification state uses
the dedicated bucket, KMS key and S3 native `use_lockfile`; it never shares the
production Terraform bucket, key or state prefix.

### H2 build authority is qualification-only

H2 may provision a dedicated native x86 build host after G0 is approved and
applied. Its instance role is a workload role, not a bootstrap or state role,
and must have no permission to discover or read production runtime resources.
The host accepts source only as an exact reviewed Git commit SHA and may write
artifacts only below a content-addressed qualification artifact prefix. The
source SHA, build recipe identity and resulting digests become evidence inputs;
mutable branch names and mutable artifact tags are not release inputs.

Administrative access is through Systems Manager Session Manager only. The
host has no inbound security-group rules, public SSH or reusable production
credentials. H2 owns the instance, profile, artifact prefix, egress boundary
and lifecycle policy in a later state under the backend emitted by G0. The
current sizing candidate is `c7i.12xlarge` with 500 GiB gp3, but sizing is an
operational input rather than part of this trust contract.

### A saved plan is accepted only through the machine contract

The checked-in validator consumes `terraform show -json` output. For the G0
create plan it requires all of the following:

1. the exact account, region, namespace, cell id and required tag set;
2. the deterministic manifest seed emitted by Terraform, byte-for-byte after
   canonical JSON encoding;
3. exactly the bootstrap resource addresses and create actions declared by
   the contract--no update, replace, delete, import or drift;
4. exact tags on every taggable authority resource;
5. no concrete existing AWS resource ID, non-qualification ARN/name, or value
   present in the read-only production denylist;
6. no unapproved data-source read or unknown identity field.

The denylist is an external observation generated immediately before the
plan. It is required input to validation and is not a source of Terraform
values. Namespace/ID checks remain authoritative even if the observation is
incomplete. Wrong account, region or namespace and production create/update/
delete decoys are executable negative tests.

Only the exact saved plan whose JSON passed this gate may be sent for
independent review. `terraform apply` must consume that saved plan; replanning
between review and apply, `-target`, console mutation, imports and shell
provisioners are not accepted paths.

### The manifest is the handoff between G0 and later phases

Terraform emits a deterministic manifest seed containing schema version,
environment identity, an explicit `environment_is_production=false`, account,
region, namespace, cell id, required tags, state bucket, KMS alias, state key
prefix and state-role ARN. The boolean prevents an evidence consumer from
mistaking the production AWS account boundary for a production execution
environment. G1--G3 extend a versioned environment manifest from this seed;
they do not rediscover these values from mutable AWS names or operator shell
state.

The source commit, candidate commit, controller commit and artifact digests
belong to the RC/qualification evidence manifest defined by F/H. They are not
smuggled into this bootstrap state.

## Explicit non-goals

- G0 does not create the qualification VPC, EKS, RDS, workers, DNS or evidence
  platform. Those belong to G1--G3.
- G0 does not create the H2 build host or artifact store. It reserves their
  authority boundary and backend handoff; H2 provisions them after review.
- G0 does not run a live apply before independent review of the exact saved
  plan.
- G0 does not enable production Multi-AZ behavior. Later modules retain
  per-AZ subnet/NAT and database Multi-AZ inputs without activating that
  product capability in this phase.
- G0 does not make the production principal or production Terraform backend a
  normal qualification credential.

## Consequences

The qualification cell can use the production AWS account without sharing a
production failure domain at the resource or state layer. The first bootstrap
still needs one powerful reviewed action by the existing operator; that
exception is small, visible and cannot be inherited by the qualification
controller.

Plan validation is deliberately stricter than ordinary Terraform. A reconcile
plan for an already-created bootstrap requires a new contract mode rather than
quietly widening the initial-create contract. This trades convenience for an
auditable boundary exactly where a mistaken update or destroy would be most
expensive.
