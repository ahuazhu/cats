locals {
  build_role_name = "${local.name_prefix}-host"
}

data "aws_iam_policy_document" "build_assume_role" {
  statement {
    sid     = "Ec2Only"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "build_permissions" {
  statement {
    sid       = "SsmRegistration"
    actions   = ["ssm:UpdateInstanceInformation"]
    resources = ["*"]
  }

  statement {
    sid = "SsmMessageChannels"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }

  statement {
    sid     = "PublishContentAddressedObjects"
    actions = ["s3:PutObject"]
    resources = [
      "${local.artifact_bucket_arn}/artifacts/sha256/*",
      "${local.artifact_bucket_arn}/evidence/sha256/*",
    ]
  }

  statement {
    sid = "EncryptPublishedObjects"
    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = [local.artifact_kms_alias]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["arn:aws:s3:::${local.artifact_bucket_name}/*"]
    }
  }

  statement {
    sid       = "DescribePublishedArtifactsKey"
    actions   = ["kms:DescribeKey"]
    resources = ["arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = [local.artifact_kms_alias]
    }
  }

  statement {
    sid = "ReadControllerPublishedSource"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]
    resources = [
      "${local.source_bucket_arn}/source/bundles/sha256/*",
      "${local.source_bucket_arn}/source/manifests/sha256/*",
    ]
  }

  statement {
    sid       = "DecryptControllerPublishedSource"
    actions   = ["kms:Decrypt"]
    resources = ["arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = [local.source_kms_alias]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${local.source_bucket_arn}/source/*"]
    }
  }

  statement {
    sid       = "DescribeControllerSourceKey"
    actions   = ["kms:DescribeKey"]
    resources = ["arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = [local.source_kms_alias]
    }
  }
}

resource "aws_iam_policy" "build_boundary" {
  name        = "${local.name_prefix}-boundary"
  description = "Maximum authority of the qualification build host"
  policy      = data.aws_iam_policy_document.build_permissions.json

  tags = {
    Name      = "${local.name_prefix}-boundary"
    Component = "build-host"
  }
}

resource "aws_iam_role" "build" {
  name                 = local.build_role_name
  description          = "Qualification-only build host; cannot read runtime production data"
  assume_role_policy   = data.aws_iam_policy_document.build_assume_role.json
  permissions_boundary = local.build_boundary_arn
  max_session_duration = 3600

  tags = {
    Name      = local.build_role_name
    Component = "build-host"
  }

  depends_on = [aws_iam_policy.build_boundary]

  lifecycle {
    # The separate aws_iam_role_policy.build resource is the sole owner. The
    # provider also mirrors inline policies into this computed legacy field.
    ignore_changes = [inline_policy]
  }
}

resource "aws_iam_role_policy" "build" {
  name   = "${local.name_prefix}-minimum"
  role   = aws_iam_role.build.id
  policy = data.aws_iam_policy_document.build_permissions.json
}

resource "aws_iam_instance_profile" "build" {
  name = local.build_role_name
  role = aws_iam_role.build.name

  tags = {
    Name      = local.build_role_name
    Component = "build-host"
  }
}
