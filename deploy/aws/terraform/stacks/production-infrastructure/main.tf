data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  expected_platform_alert_topic_arn = join(":", [
    "arn",
    var.expected_aws_partition,
    "sns",
    var.aws_region,
    var.expected_account_id,
    "cats-${var.environment}-alerts",
  ])
}

resource "terraform_data" "platform_alert_topic_identity" {
  input = {
    account_id = data.aws_caller_identity.current.account_id
    partition  = data.aws_partition.current.partition
    region     = data.aws_region.current.region
    topic_arn  = var.platform_alert_sns_topic_arn
  }

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
      error_message = "Resolved AWS caller account does not match expected_account_id."
    }

    precondition {
      condition     = data.aws_partition.current.partition == var.expected_aws_partition
      error_message = "Resolved AWS partition does not match expected_aws_partition."
    }

    precondition {
      condition     = data.aws_region.current.region == var.aws_region
      error_message = "Resolved AWS provider region does not match aws_region."
    }

    precondition {
      condition     = var.platform_alert_sns_topic_arn == local.expected_platform_alert_topic_arn
      error_message = "Platform alert topic is not the exact expected production topic."
    }
  }
}

module "usage_infrastructure" {
  source = "../../modules/usage-infrastructure"

  name_prefix                     = "cats"
  environment                     = var.environment
  eks_cluster_name                = var.eks_cluster_name
  archive_bucket_name             = var.usage_archive_bucket_name
  chunkstore_manifest_bucket_name = var.chunkstore_bucket_name
  chunkstore_prefix               = var.chunkstore_prefix
  archive_object_lock_days        = var.usage_archive_object_lock_days
  kinesis_shard_count             = var.usage_kinesis_shard_count
  kinesis_retention_hours         = var.usage_kinesis_retention_hours
  consumer_lag_alarm_threshold_ms = var.usage_consumer_lag_alarm_threshold_ms
  alarm_action_arns               = [var.platform_alert_sns_topic_arn]
  tags                            = var.tags

  depends_on = [terraform_data.platform_alert_topic_identity]
}

# Clean-slate cutover lane: the reset executor requires the fresh Kinesis
# stream, checkpoint table and usage archive to exist in parallel with the old
# set under strictly different names (deploy/aws/production-clean-slate-reset.py
# rejects any collision). Guard the half-configured case before the module can
# fail deep inside S3 bucket creation or, worse, alias the old archive.
resource "terraform_data" "fresh_usage_inputs" {
  count = var.fresh_usage_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.fresh_usage_archive_bucket_name != ""
      error_message = "fresh_usage_enabled requires fresh_usage_archive_bucket_name."
    }

    precondition {
      condition     = var.fresh_usage_archive_bucket_name != var.usage_archive_bucket_name
      error_message = "The fresh usage archive bucket must not reuse the old usage archive bucket name; the reset executor rejects the collision."
    }

    # The old instance binds the module-default cats-controld service account,
    # and EKS Pod Identity allows one association per cluster, namespace and
    # service account. The fresh association must not claim the same one while
    # both instances exist.
    precondition {
      condition     = var.fresh_usage_service_account_name != "cats-controld"
      error_message = "fresh_usage_service_account_name must differ from the old instance's cats-controld service account while both usage sets exist."
    }
  }
}

# Second usage-infrastructure instance for the cutover. Every regional name in
# the module derives from "<name_prefix>-<environment>-usage", so suffixing the
# prefix yields the fully disjoint fresh set -- stream, checkpoint table,
# producer/consumer/replay policies, pipeline role and alarms -- without
# changing the module. The archive bucket name is global and passed explicitly.
module "usage_fresh" {
  source = "../../modules/usage-infrastructure"

  count = var.fresh_usage_enabled ? 1 : 0

  name_prefix                     = "cats-${var.fresh_usage_name_suffix}"
  environment                     = var.environment
  eks_cluster_name                = var.eks_cluster_name
  archive_bucket_name             = var.fresh_usage_archive_bucket_name
  chunkstore_manifest_bucket_name = var.chunkstore_bucket_name
  chunkstore_prefix               = var.chunkstore_prefix
  archive_object_lock_days        = var.usage_archive_object_lock_days
  kinesis_shard_count             = var.usage_kinesis_shard_count
  kinesis_retention_hours         = var.usage_kinesis_retention_hours
  consumer_lag_alarm_threshold_ms = var.usage_consumer_lag_alarm_threshold_ms
  alarm_action_arns               = [var.platform_alert_sns_topic_arn]
  usage_service_account_name      = var.fresh_usage_service_account_name
  tags                            = var.tags

  depends_on = [
    terraform_data.platform_alert_topic_identity,
    terraform_data.fresh_usage_inputs,
  ]
}

locals {
  metal_worker_enabled = (
    var.metal_worker_enabled != null
    ? var.metal_worker_enabled
    : length(var.metal_worker_instances) > 0
  )
}

# Guard the half-configured case explicitly. Without it, enabling the worker
# without a bundle fails deep inside the module on an empty S3 key.
resource "terraform_data" "metal_worker_inputs" {
  count = local.metal_worker_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition = alltrue([
        length(var.metal_worker_instances) > 0,
        var.metal_worker_instance_role_name != "",
        var.worker_bundle_path != "",
        var.worker_bundle_sha256 != "",
      ])
      error_message = "The metal worker release path needs worker instances, instance role, bundle path and bundle sha256. Leave metal_worker_instances empty to skip it until the hardware exists."
    }
  }
}

# The single-worker deployment used one unkeyed association. Terraform must
# see the fleet-keyed address as the same resource: a destroy-and-recreate
# would re-run the deployment on a worker that may not be drained.
moved {
  from = module.metal_worker_deployment[0].aws_ssm_association.worker_deploy
  to   = module.metal_worker_deployment[0].aws_ssm_association.worker_deploy["metal-1"]
}

module "metal_worker_deployment" {
  source = "../../modules/metal-worker-deployment"

  count = local.metal_worker_enabled ? 1 : 0

  name_prefix                = "cats"
  environment                = var.environment
  expected_account_id        = var.expected_account_id
  expected_aws_partition     = var.expected_aws_partition
  aws_region                 = var.aws_region
  artifact_bucket_name       = var.worker_artifact_bucket_name
  worker_bundle_path         = var.worker_bundle_path
  worker_bundle_sha256       = var.worker_bundle_sha256
  instances                  = var.metal_worker_instances
  deploy_instances           = var.metal_worker_deploy_instances
  instance_role_name         = var.metal_worker_instance_role_name
  worker_runtime_secret_data = var.worker_runtime_secret_data
  chunkstore_prefix          = var.chunkstore_prefix
  control_postgres_schema    = var.control_postgres_schema
  worker_base_environment    = var.worker_base_environment

  # The worker reads the database password from its authority instead of a copy.
  database_master_user_secret_arn = var.database_master_user_secret_arn
  worker_managed_environment      = var.worker_managed_environment

  tags = var.tags

  depends_on = [
    terraform_data.platform_alert_topic_identity,
    terraform_data.metal_worker_inputs,
  ]
}

# AWS identity for the in-cluster credential refresher (ADR-0029, #77).
#
# It lives in this state rather than the application state on purpose. The
# application state is applied by the branch-pinned GitHub role, whose
# `iam:CreateRole` is scoped to one specific role ARN; letting the automated
# deployment mint IAM roles and Pod Identity associations would widen it well
# past what it needs. The Kubernetes objects that use this identity are in the
# application state, which is exactly the split of privilege they should have.
#
# Apply this before the deployment that creates the ServiceAccount. An
# association may name a ServiceAccount that does not exist yet; the reverse
# leaves the CronJob without credentials and it fails closed on its first run.

data "aws_iam_policy_document" "credential_refresher_assume" {
  count = var.database_master_user_secret_arn == null ? 0 : 1

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "credential_refresher" {
  count = var.database_master_user_secret_arn == null ? 0 : 1

  name               = "cats-${var.environment}-credential-refresher"
  description        = "Reads the RDS managed master secret so the control plane's Secret can be reconciled against it."
  assume_role_policy = data.aws_iam_policy_document.credential_refresher_assume[0].json

  tags = var.tags
}

# One action, one secret. The refresher never writes to Secrets Manager and
# never reads anything else.
data "aws_iam_policy_document" "credential_refresher" {
  count = var.database_master_user_secret_arn == null ? 0 : 1

  statement {
    sid       = "ReadDatabaseMasterUserSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.database_master_user_secret_arn]
  }
}

resource "aws_iam_role_policy" "credential_refresher" {
  count = var.database_master_user_secret_arn == null ? 0 : 1

  name   = "read-database-master-user-secret"
  role   = aws_iam_role.credential_refresher[0].name
  policy = data.aws_iam_policy_document.credential_refresher[0].json
}

resource "aws_eks_pod_identity_association" "credential_refresher" {
  count = var.database_master_user_secret_arn == null ? 0 : 1

  cluster_name    = var.eks_cluster_name
  namespace       = var.credential_refresher_namespace
  service_account = var.credential_refresher_service_account
  role_arn        = aws_iam_role.credential_refresher[0].arn

  tags = var.tags
}
