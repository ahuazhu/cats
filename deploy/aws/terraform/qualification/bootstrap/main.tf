provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = local.required_tags
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

  state_bucket_name = "${var.qualification_namespace}-tfstate-${var.expected_account_id}-${var.aws_region}"
  state_key_prefix  = "architecture-v2"
  state_kms_alias   = "alias/${var.qualification_namespace}-terraform-state"
  state_role_name   = "${var.qualification_namespace}-terraform-state"

  manifest_seed = {
    schema_version            = 1
    environment               = "qualification"
    environment_is_production = false
    account_id                = var.expected_account_id
    region                    = var.aws_region
    namespace                 = var.qualification_namespace
    cell_id                   = var.qualification_cell_id
    required_tags             = local.required_tags
    terraform_state = {
      bucket         = local.state_bucket_name
      kms_alias      = local.state_kms_alias
      key_prefix     = local.state_key_prefix
      use_lockfile   = true
      state_role_arn = "arn:${data.aws_partition.current.partition}:iam::${var.expected_account_id}:role/${local.state_role_name}"
    }
  }
}

check "qualification_identity" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
    error_message = "AWS caller is not in the explicitly approved qualification account."
  }

  assert {
    condition     = data.aws_region.current.region == var.aws_region
    error_message = "AWS provider region differs from the qualification contract."
  }

  assert {
    condition     = startswith(var.bootstrap_principal_arn, "arn:${data.aws_partition.current.partition}:iam::${var.expected_account_id}:")
    error_message = "bootstrap principal must belong to the approved qualification account."
  }
}

data "aws_iam_policy_document" "state_key" {
  statement {
    sid       = "ExactBootstrapAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.bootstrap_principal_arn]
    }
  }

  # Using the account principal plus aws:PrincipalArn lets the initial plan
  # name the state role before that role exists, without delegating the key to
  # every IAM identity in the account.
  statement {
    sid    = "ExactStateRoleUse"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.expected_account_id}:root"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:${data.aws_partition.current.partition}:iam::${var.expected_account_id}:role/${local.state_role_name}"]
    }
  }
}

resource "aws_kms_key" "state" {
  description             = "${var.qualification_namespace} Terraform state"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.state_key.json

  tags = merge(local.required_tags, {
    Name      = "${var.qualification_namespace}-terraform-state"
    Component = "terraform-state"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "state" {
  name          = local.state_kms_alias
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "state" {
  bucket        = local.state_bucket_name
  force_destroy = false

  tags = merge(local.required_tags, {
    Name      = local.state_bucket_name
    Component = "terraform-state"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.state.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyCrossAccountPrincipals"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.expected_account_id]
    }
  }

  statement {
    sid    = "DenyWrongExplicitEncryptionKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.state.arn}/*"]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["false"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.state.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json
}

data "aws_iam_policy_document" "state_role_trust" {
  statement {
    sid     = "ExactBootstrapPrincipal"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.bootstrap_principal_arn]
    }
  }
}

resource "aws_iam_role" "state" {
  name                 = local.state_role_name
  description          = "State-only role for ${var.qualification_namespace}; no runtime AWS authority"
  assume_role_policy   = data.aws_iam_policy_document.state_role_trust.json
  max_session_duration = 3600

  tags = merge(local.required_tags, {
    Name      = local.state_role_name
    Component = "terraform-state"
  })

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_policy_document" "state_access" {
  statement {
    sid = "StateBucketMetadata"
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.state.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        local.state_key_prefix,
        "${local.state_key_prefix}/*",
      ]
    }
  }

  statement {
    sid = "StateAndNativeLockfile"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.state.arn}/${local.state_key_prefix}/*"]
  }

  statement {
    sid = "StateEncryptionOnly"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.state.arn]
  }
}

resource "aws_iam_role_policy" "state" {
  name   = "${var.qualification_namespace}-terraform-state-access"
  role   = aws_iam_role.state.id
  policy = data.aws_iam_policy_document.state_access.json
}
