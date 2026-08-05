# A deliberately separate GitHub identity for the issue #124 temporary worker.
# The ordinary release role cannot mutate EC2 or SSM. This role is opt-in,
# branch-pinned, and can create/operate only one visibly tagged class of worker.
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "github_qualification_assume" {
  count = var.github_qualification_worker_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.github_release.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${coalesce(var.github_subject_repository, var.github_repository)}:ref:refs/heads/${var.github_default_branch}"]
    }
  }
}

resource "aws_iam_role" "github_qualification_worker" {
  count = var.github_qualification_worker_enabled ? 1 : 0

  name                 = "${var.name_prefix}-${var.environment}-q124-worker"
  description          = "Main-only temporary worker qualification for Cats issue 124"
  assume_role_policy   = data.aws_iam_policy_document.github_qualification_assume[0].json
  max_session_duration = 7200
  tags                 = merge(var.tags, { CatsIssue = "124" })
}

data "aws_ami" "qualification_worker" {
  count = var.github_qualification_worker_enabled ? 1 : 0

  executable_users = ["self"]

  filter {
    name   = "image-id"
    values = [var.metal_worker_ami]
  }
}

module "github_qualification_worker_policy" {
  count  = var.github_qualification_worker_enabled ? 1 : 0
  source = "../../modules/qualification-worker-policy"

  partition  = data.aws_partition.current.partition
  region     = var.aws_region
  account_id = data.aws_caller_identity.current.account_id
  ami_id     = var.metal_worker_ami
  snapshot_arns = toset([
    for snapshot_id in compact([
      for mapping in data.aws_ami.qualification_worker[0].block_device_mappings :
      try(mapping.ebs.snapshot_id, "")
    ]) : "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/${snapshot_id}"
  ])
  subnet_id            = module.network.private_subnet_ids[0]
  security_group_id    = aws_security_group.metal_worker.id
  instance_type        = var.metal_worker_instance_type
  instance_profile_arn = aws_iam_instance_profile.metal_worker.arn
  worker_role_arn      = aws_iam_role.metal_worker.arn
  artifact_bucket_arn  = var.github_qualification_artifact_bucket_arn
}

resource "aws_iam_role_policy" "github_qualification_worker" {
  count  = var.github_qualification_worker_enabled ? 1 : 0
  name   = "issue-124-temporary-worker"
  role   = aws_iam_role.github_qualification_worker[0].id
  policy = module.github_qualification_worker_policy[0].json
}
