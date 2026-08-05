module "usage_infrastructure" {
  source = "../../modules/usage-infrastructure"

  name_prefix                     = "cats"
  environment                     = var.environment
  eks_cluster_name                = var.eks_cluster_name
  archive_bucket_name             = var.usage_archive_bucket_name
  archive_object_lock_days        = var.usage_archive_object_lock_days
  kinesis_shard_count             = var.usage_kinesis_shard_count
  kinesis_retention_hours         = var.usage_kinesis_retention_hours
  consumer_lag_alarm_threshold_ms = var.usage_consumer_lag_alarm_threshold_ms
  alarm_action_arns               = var.alarm_sns_topic_arns
  tags                            = var.tags
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
        length(var.worker_runtime_secret_data) > 0,
        length(trimspace(var.route_grant_public_key_pem)) > 0,
      ])
      error_message = "The metal worker release path needs worker instances, instance role, bundle path, bundle sha256, runtime secret data and the Route Grant public key. Leave metal_worker_instances empty to skip it until the hardware exists."
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
  artifact_bucket_name       = var.worker_artifact_bucket_name
  worker_bundle_path         = var.worker_bundle_path
  worker_bundle_sha256       = var.worker_bundle_sha256
  instances                  = var.metal_worker_instances
  deploy_instances           = var.metal_worker_deploy_instances
  instance_role_name         = var.metal_worker_instance_role_name
  worker_runtime_secret_data = var.worker_runtime_secret_data
  route_grant_public_key_pem = var.route_grant_public_key_pem
  worker_base_environment    = var.worker_base_environment

  # The worker reads the database password from its authority instead of a copy.
  database_master_user_secret_arn = var.database_master_user_secret_arn
  worker_managed_environment      = var.worker_managed_environment

  tags = var.tags
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
