locals {
  source_bucket_name   = "${var.qualification_namespace}-build-source-${var.expected_account_id}-${var.aws_region}"
  source_bucket_arn    = "arn:${data.aws_partition.current.partition}:s3:::${local.source_bucket_name}"
  source_kms_alias     = "alias/${var.qualification_namespace}-build-source"
  source_kms_alias_arn = "arn:${data.aws_partition.current.partition}:kms:${var.aws_region}:${var.expected_account_id}:${local.source_kms_alias}"
  source_prefixes = [
    "source/bundles/sha256/",
    "source/manifests/sha256/",
  ]
}

data "aws_iam_policy_document" "source_key" {
  statement {
    sid       = "EnableAccountIAMPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.expected_account_id}:root"]
    }
  }
}

resource "aws_kms_key" "source" {
  description             = "Qualification controller-to-build-host source delivery only"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.source_key.json

  tags = {
    Name      = "${local.name_prefix}-source"
    Component = "build-source"
  }
}

resource "aws_kms_alias" "source" {
  name          = local.source_kms_alias
  target_key_id = aws_kms_key.source.key_id
}

resource "aws_s3_bucket" "source" {
  bucket        = local.source_bucket_name
  force_destroy = false

  tags = {
    Name      = local.source_bucket_name
    Component = "build-source"
  }
}

resource "aws_s3_bucket_ownership_controls" "source" {
  bucket = aws_s3_bucket.source.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "source" {
  bucket = aws_s3_bucket.source.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = aws_s3_bucket.source.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  bucket = aws_s3_bucket.source.id

  rule {
    # Object-level encryption context lets the host role constrain KMS decrypt
    # to the two approved source prefixes. S3 Bucket Keys use the bucket ARN
    # instead and would erase that prefix boundary.
    bucket_key_enabled = false

    apply_server_side_encryption_by_default {
      kms_master_key_id = local.source_kms_alias_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

data "aws_iam_policy_document" "source_bucket" {
  statement {
    sid    = "DenyObjectDeletion"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = ["${local.source_bucket_arn}/source/*"]
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      local.source_bucket_arn,
      "${local.source_bucket_arn}/*",
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
      local.source_bucket_arn,
      "${local.source_bucket_arn}/*",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.expected_account_id]
    }
  }

  statement {
    sid    = "DenyMissingExplicitKmsKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${local.source_bucket_arn}/*"]

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["true"]
    }
  }

  statement {
    sid    = "DenyWrongExplicitKmsKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${local.source_bucket_arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.source.arn]
    }
  }

}

resource "aws_s3_bucket_policy" "source" {
  bucket = aws_s3_bucket.source.id
  policy = data.aws_iam_policy_document.source_bucket.json
}
