locals {
  deployer_boundary_name = "${local.reconcile_role_name}-boundary"
  deployer_boundary_arn  = "arn:aws:iam::${var.expected_account_id}:policy/${local.deployer_boundary_name}"
  build_boundary_arn     = "arn:aws:iam::${var.expected_account_id}:policy/${local.name_prefix}-boundary"
  build_role_arn         = "arn:aws:iam::${var.expected_account_id}:role/${local.build_role_name}"
  build_profile_arn      = "arn:aws:iam::${var.expected_account_id}:instance-profile/${local.build_role_name}"
}

data "aws_iam_policy_document" "deployer_assume_role" {
  statement {
    sid     = "ExactFormationPrincipal"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.formation_principal_arn]
    }
  }
}

# Reconciliation is deliberately read-only. EC2 RunInstances cannot constrain
# user-data bytes, and same-account IAM or bucket-policy mutation could bypass
# an implicit permissions-boundary deny. Every create, update, replacement or
# deletion therefore requires a new formation-mode saved plan and independent
# review. This role exists only for the mandatory post-apply no-op/drift gate.
data "aws_iam_policy_document" "deployer_permissions" {
  statement {
    sid = "ExactIamInventory"
    actions = [
      "iam:GetInstanceProfile",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
      "iam:ListInstanceProfileTags",
      "iam:ListPolicyTags",
      "iam:ListPolicyVersions",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
    ]
    resources = [
      local.build_boundary_arn,
      local.build_profile_arn,
      local.build_role_arn,
      local.deployer_boundary_arn,
      local.reconcile_role_arn,
    ]
  }

  statement {
    sid       = "Ec2InventoryOnly"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }

  statement {
    sid = "ExactBucketMetadataOnly"
    actions = [
      "s3:GetBucket*",
      "s3:GetEncryptionConfiguration",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${local.artifact_bucket_name}",
      "arn:aws:s3:::${local.source_bucket_name}",
    ]
  }

  statement {
    sid = "ExactKmsMetadataOnly"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values = [
        local.artifact_kms_alias,
        local.volume_kms_alias,
      ]
    }
  }

  statement {
    sid = "SourceKmsMetadataOnly"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = [local.source_kms_alias]
    }
  }

  statement {
    sid       = "KmsAliasInventoryOnly"
    actions   = ["kms:ListAliases"]
    resources = ["*"]
  }
}

check "deployer_boundary_policy_size" {
  assert {
    condition     = length(data.aws_iam_policy_document.deployer_permissions.json) <= 6144
    error_message = "read-only reconciler permissions boundary exceeds the IAM 6,144-byte managed-policy limit."
  }
}

resource "aws_iam_policy" "deployer_boundary" {
  name        = local.deployer_boundary_name
  description = "Immutable maximum authority of the H2 qualification Terraform deployer"
  policy      = data.aws_iam_policy_document.deployer_permissions.json

  tags = {
    Name      = local.deployer_boundary_name
    Component = "build-deployer"
  }
}

resource "aws_iam_role" "deployer" {
  name                 = local.reconcile_role_name
  description          = "Read-only H2 drift and no-op-plan reconciler; all mutations require formation review"
  assume_role_policy   = data.aws_iam_policy_document.deployer_assume_role.json
  permissions_boundary = local.deployer_boundary_arn
  max_session_duration = 3600

  tags = {
    Name      = local.reconcile_role_name
    Component = "build-deployer"
  }

  depends_on = [aws_iam_policy.deployer_boundary]

  lifecycle {
    # The separate aws_iam_role_policy.deployer resource is the sole owner.
    # Ignoring the provider mirror prevents a permanent parent/child drift.
    ignore_changes = [inline_policy]
  }
}

resource "aws_iam_role_policy" "deployer" {
  name   = "${local.reconcile_role_name}-reconcile"
  role   = aws_iam_role.deployer.id
  policy = data.aws_iam_policy_document.deployer_permissions.json
}
