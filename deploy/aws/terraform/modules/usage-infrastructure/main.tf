locals {
  resource_name = "${var.name_prefix}-${var.environment}-usage"
  tags = merge(var.tags, {
    Component   = "usage-billing"
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = "Cats"
  })
}

data "aws_partition" "current" {}

resource "aws_kinesis_stream" "usage" {
  name             = local.resource_name
  shard_count      = var.kinesis_shard_count
  retention_period = var.kinesis_retention_hours

  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  shard_level_metrics = [
    "IncomingBytes",
    "IncomingRecords",
    "OutgoingBytes",
    "OutgoingRecords",
    "ReadProvisionedThroughputExceeded",
    "WriteProvisionedThroughputExceeded",
  ]

  tags = local.tags
}

resource "aws_s3_bucket" "archive" {
  bucket              = var.archive_bucket_name
  force_destroy       = var.archive_force_destroy
  object_lock_enabled = true

  tags = merge(local.tags, {
    DataClass = "immutable-usage-evidence"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket = aws_s3_bucket.archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    bucket_key_enabled = false

    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    default_retention {
      mode = var.archive_object_lock_mode
      days = var.archive_object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.archive]
}

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    id     = "usage-evidence-tiering"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = var.archive_standard_ia_after_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.archive_deep_archive_after_days
      storage_class = "DEEP_ARCHIVE"
    }

    noncurrent_version_transition {
      noncurrent_days = var.archive_standard_ia_after_days
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = var.archive_deep_archive_after_days
      storage_class   = "DEEP_ARCHIVE"
    }
  }

  depends_on = [
    aws_s3_bucket_object_lock_configuration.archive,
    aws_s3_bucket_versioning.archive,
  ]
}

data "aws_iam_policy_document" "archive_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.archive.arn,
      "${aws_s3_bucket.archive.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "archive" {
  bucket = aws_s3_bucket.archive.id
  policy = data.aws_iam_policy_document.archive_tls_only.json
}

resource "aws_dynamodb_table" "consumer_leases" {
  name         = "${local.resource_name}-consumer-leases"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "lease_key"

  attribute {
    name = "lease_key"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
}

data "aws_iam_policy_document" "producer" {
  statement {
    sid = "PublishUsageCheckpoints"
    actions = [
      "kinesis:PutRecord",
    ]
    resources = [aws_kinesis_stream.usage.arn]
  }
}

resource "aws_iam_policy" "producer" {
  name        = "${local.resource_name}-producer"
  description = "Publish batched Cats usage checkpoints."
  policy      = data.aws_iam_policy_document.producer.json
  tags        = local.tags
}

data "aws_iam_policy_document" "consumer" {
  statement {
    sid = "ConsumeUsageCheckpoints"
    actions = [
      "kinesis:GetRecords",
      "kinesis:GetShardIterator",
      "kinesis:ListShards",
    ]
    resources = [aws_kinesis_stream.usage.arn]
  }

  statement {
    sid = "PersistUsageProjectorCheckpoint"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
    ]
    resources = [aws_dynamodb_table.consumer_leases.arn]
  }

  statement {
    sid = "WriteUsageArchive"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.archive.arn}/*"]
  }
}

resource "aws_iam_policy" "consumer" {
  name        = "${local.resource_name}-consumer"
  description = "Consume usage checkpoints and write immutable archive batches."
  policy      = data.aws_iam_policy_document.consumer.json
  tags        = local.tags
}

data "aws_iam_policy_document" "replay" {
  statement {
    sid = "ListUsageArchive"
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.archive.arn]
  }

  statement {
    sid       = "ReadUsageArchive"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.archive.arn}/*"]
  }
}

resource "aws_iam_policy" "replay" {
  name        = "${local.resource_name}-replay"
  description = "Read-only backfill and reconciliation access to usage evidence."
  policy      = data.aws_iam_policy_document.replay.json
  tags        = local.tags
}

data "aws_iam_policy_document" "pod_identity_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pipeline" {
  name               = "${local.resource_name}-pipeline"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "pipeline_producer" {
  role       = aws_iam_role.pipeline.name
  policy_arn = aws_iam_policy.producer.arn
}

resource "aws_iam_role_policy_attachment" "pipeline_consumer" {
  role       = aws_iam_role.pipeline.name
  policy_arn = aws_iam_policy.consumer.arn
}

# The Control Plane resolves only the immutable manifest object addressed by a
# request digest. It cannot list the bucket, read image data/volume objects, or
# mutate any ChunkStore key.
data "aws_iam_policy_document" "image_manifest_reader" {
  statement {
    sid     = "ReadExactImageManifestNamespace"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::${var.chunkstore_manifest_bucket_name}/${var.chunkstore_prefix}/images/*/manifest.json"
    ]
  }
}

resource "aws_iam_role_policy" "image_manifest_reader" {
  name   = "read-chunkstore-image-manifests"
  role   = aws_iam_role.pipeline.name
  policy = data.aws_iam_policy_document.image_manifest_reader.json
}

resource "aws_eks_pod_identity_association" "pipeline" {
  cluster_name    = var.eks_cluster_name
  namespace       = var.usage_service_account_namespace
  service_account = var.usage_service_account_name
  role_arn        = aws_iam_role.pipeline.arn

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "write_throttled" {
  alarm_name                = "${local.resource_name}-write-throttled"
  alarm_description         = "Usage checkpoint publication exceeded provisioned Kinesis capacity."
  namespace                 = "AWS/Kinesis"
  metric_name               = "WriteProvisionedThroughputExceeded"
  statistic                 = "Sum"
  period                    = 60
  evaluation_periods        = 1
  comparison_operator       = "GreaterThanThreshold"
  threshold                 = 0
  treat_missing_data        = "notBreaching"
  alarm_actions             = var.alarm_action_arns
  ok_actions                = var.alarm_action_arns
  insufficient_data_actions = []

  dimensions = {
    StreamName = aws_kinesis_stream.usage.name
  }

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "read_throttled" {
  alarm_name                = "${local.resource_name}-read-throttled"
  alarm_description         = "Usage consumers exceeded provisioned Kinesis read capacity."
  namespace                 = "AWS/Kinesis"
  metric_name               = "ReadProvisionedThroughputExceeded"
  statistic                 = "Sum"
  period                    = 60
  evaluation_periods        = 1
  comparison_operator       = "GreaterThanThreshold"
  threshold                 = 0
  treat_missing_data        = "notBreaching"
  alarm_actions             = var.alarm_action_arns
  ok_actions                = var.alarm_action_arns
  insufficient_data_actions = []

  dimensions = {
    StreamName = aws_kinesis_stream.usage.name
  }

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "consumer_lag" {
  alarm_name                = "${local.resource_name}-consumer-lag"
  alarm_description         = "Usage projector lag exceeded the provisional billing freshness target."
  namespace                 = "AWS/Kinesis"
  metric_name               = "GetRecords.IteratorAgeMilliseconds"
  statistic                 = "Maximum"
  period                    = 60
  evaluation_periods        = 2
  comparison_operator       = "GreaterThanThreshold"
  threshold                 = var.consumer_lag_alarm_threshold_ms
  treat_missing_data        = "notBreaching"
  alarm_actions             = var.alarm_action_arns
  ok_actions                = var.alarm_action_arns
  insufficient_data_actions = []

  dimensions = {
    StreamName = aws_kinesis_stream.usage.name
  }

  tags = local.tags
}
