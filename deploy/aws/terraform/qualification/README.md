# Qualification cell Terraform

This directory owns only the Architecture V2 qualification cell. It runs in
the production AWS account but must never reuse or target a production
resource.

G0 contains the isolated backend bootstrap and the saved-plan contract. G1--G3
add platform, management-plane and evidence states only after G0's exact saved
plan has passed independent review.

## G0 bootstrap workflow

The bootstrap configuration intentionally has local state because it creates
the qualification backend. Keep that state in an approved encrypted operator
vault.

After a reviewed apply, copy the state to
`architecture-v2/bootstrap-snapshots/<state-sha256>.tfstate` as an immutable
recovery snapshot in the versioned, KMS-encrypted qualification bucket. This
object is not an active backend or migration target, takes no Terraform lock,
and must not be consumed through `terraform_remote_state`. Local bootstrap
state remains authoritative.

```sh
cd deploy/aws/terraform/qualification/bootstrap
cp bootstrap.tfvars.example bootstrap.auto.tfvars
terraform init
terraform validate
terraform plan -out=qualification-bootstrap.tfplan
terraform show -json qualification-bootstrap.tfplan > qualification-bootstrap.plan.json

python3 ../tools/validate_saved_plan.py \
  --plan-json qualification-bootstrap.plan.json \
  --contract ../contracts/bootstrap-create-v1.json \
  --forbidden-inventory /approved/path/production-resource-denylist.json \
  --template-value "account_id=$QUALIFICATION_AWS_ACCOUNT_ID" \
  --template-value "bootstrap_principal_arn=$QUALIFICATION_BOOTSTRAP_PRINCIPAL_ARN"
```

The two environment variables above are shell conveniences in this example,
not implicit inputs to Terraform or the validator. The values must also be
present explicitly in the reviewed `bootstrap.auto.tfvars` and command.

## Shared saved-plan gate

`tools/validate_saved_plan.py` contains no G0 or H2 resource semantics. Each
stack supplies a versioned JSON contract declaring its human-readable resource
label, exact plan variables, manifest output and expected JSON template,
forbidden-inventory account/region, exact external ARNs, full-string owned ARN
globs, exact approved external resource identifiers, checks, data reads,
actions, tags and identity templates. Runtime values are explicit
`--template-value NAME=VALUE` arguments, and the contract declares the complete
allowed name set. ARN globs are matched against the entire ARN; a namespace
substring in an unrelated production ARN grants no authority. Concrete AWS IDs
remain denied unless the contract lists the exact token, such as H2's reviewed
Canonical AMI.

Later stacks, including H2, add a versioned contract instance and reuse this
gate. They must not copy the validator or widen the G0 contract. Create-only
means an applyable and complete plan with all declared checks passing, no
managed prior state or drift, and exactly the declared creates. Maintenance
contracts freeze every managed action plus canonical SHA-256 digests of the
complete managed transition and any explicitly reviewed drift. A policy,
user-data byte, before/after value, action, or drift change therefore requires
a new reviewed contract and saved plan.

Do not apply while #241 is awaiting saved-plan review. After approval, apply
the exact file that was reviewed:

```sh
terraform apply qualification-bootstrap.tfplan
```

Replanning, `-target`, importing resources and applying through the AWS Console
are not equivalent to that approval.

## Production denylist input

The validator requires a read-only observation with this shape:

```json
{
  "schema_version": 1,
  "observed_account_id": "123456789012",
  "observed_region": "us-east-1",
  "identifiers": [
    "vpc-0123456789abcdef0",
    "existing-production-cluster",
    "arn:aws:rds:us-east-1:123456789012:db:existing-production"
  ]
}
```

Include resource IDs, names, DNS names and ARNs for every existing production
resource family. This file is external evidence and may contain operational
inventory, so it is not committed. The validator also rejects known concrete
AWS IDs and every non-qualification identity value, which prevents an
incomplete denylist from becoming an allowlist.

## State handoff

After bootstrap, use output `backend_hcl` to create the private backend config
for later qualification states. They must use S3 native `use_lockfile`, the
qualification KMS key, and a key below the emitted `state_key_prefix`.

The H2 build-host state is one such later state. It must not extend the G0
state role with runtime permissions: H2 gets a separate qualification-only
workload role, SSM-only administration with no inbound rules, exact-SHA source
inputs, and write access only to its content-addressed qualification artifact
prefix.
