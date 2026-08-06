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
  --expected-account-id "$QUALIFICATION_AWS_ACCOUNT_ID" \
  --bootstrap-principal-arn "$QUALIFICATION_BOOTSTRAP_PRINCIPAL_ARN"
```

The two environment variables above are shell conveniences in this example,
not implicit inputs to Terraform or the validator. The values must also be
present explicitly in the reviewed `bootstrap.auto.tfvars` and command.

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
