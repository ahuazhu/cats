provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = local.required_tags
  }

  dynamic "assume_role" {
    for_each = var.formation_mode ? [] : [local.reconcile_role_arn]

    content {
      role_arn     = assume_role.value
      session_name = "cats-qualification-h2-reconcile"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  required_tags = {
    Project                = "Cats"
    Environment            = "qualification"
    QualificationNamespace = var.qualification_namespace
    QualificationCell      = var.qualification_cell_id
    ManagedBy              = "terraform"
  }

  boundary = var.qualification_manifest_seed

  name_prefix         = "${var.qualification_namespace}-build"
  reconcile_role_name = "${var.qualification_namespace}-h2-deployer"
  reconcile_role_arn  = "arn:aws:iam::${var.expected_account_id}:role/${local.reconcile_role_name}"

  availability_zone_id = "use1-az1"

  vpc_cidr            = "10.77.0.0/20"
  public_subnet_cidr  = "10.77.0.0/24"
  private_subnet_cidr = "10.77.1.0/24"
  vpc_resolver_cidr   = "10.77.0.2/32"
  time_sync_cidr      = "169.254.169.123/32"

  instance_type = "c7i.12xlarge"
  root_volume = {
    size_gib   = 500
    type       = "gp3"
    iops       = 6000
    throughput = 500
  }

  canonical_ami = jsondecode(file("${path.module}/ami/ubuntu-noble-20260714-amd64.json"))
}

check "qualification_boundary" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
    error_message = "AWS caller is not in the explicitly approved qualification account."
  }

  assert {
    condition     = data.aws_region.current.region == var.aws_region
    error_message = "AWS provider region differs from the qualification contract."
  }

  assert {
    condition = jsonencode(local.boundary) == jsonencode({
      schema_version            = 1
      environment               = "qualification"
      environment_is_production = false
      account_id                = var.expected_account_id
      region                    = var.aws_region
      namespace                 = var.qualification_namespace
      cell_id                   = var.qualification_cell_id
      required_tags             = local.required_tags
      terraform_state = {
        bucket         = "${var.qualification_namespace}-tfstate-${var.expected_account_id}-${var.aws_region}"
        kms_alias      = "alias/${var.qualification_namespace}-terraform-state"
        key_prefix     = "architecture-v2"
        use_lockfile   = true
        state_role_arn = "arn:${data.aws_partition.current.partition}:iam::${var.expected_account_id}:role/${var.qualification_namespace}-terraform-state"
      }
    })
    error_message = "G0 qualification boundary differs from the reviewed build-host contract."
  }

  assert {
    condition = var.formation_mode ? (
      data.aws_caller_identity.current.arn == var.formation_principal_arn
      ) : (
      data.aws_caller_identity.current.arn == "arn:aws:sts::${var.expected_account_id}:assumed-role/${local.reconcile_role_name}/cats-qualification-h2-reconcile"
    )
    error_message = "formation must use the exact bootstrap principal; reconciliation must use the exact H2 deployer session."
  }
}
