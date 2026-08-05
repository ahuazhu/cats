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

data "aws_iam_policy_document" "github_qualification_worker" {
  count = var.github_qualification_worker_enabled ? 1 : 0

  statement {
    sid       = "ReadEc2AndSsmInventory"
    effect    = "Allow"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeVolumes", "ssm:DescribeInstanceInformation", "ssm:GetCommandInvocation", "ssm:ListCommandInvocations"]
    resources = ["*"]
  }

  # RunInstances authorizes every resource that participates in the request.
  # The infrastructure resources are exact; new instance/volume/ENI ARNs are
  # necessarily wildcard but are coupled to mandatory request tags.
  statement {
    sid     = "LaunchWithFixedInfrastructure"
    effect  = "Allow"
    actions = ["ec2:RunInstances"]
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/${var.metal_worker_ami}",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:subnet/${module.network.private_subnet_ids[0]}",
      aws_security_group.metal_worker.arn,
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:network-interface/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:volume/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "ec2:InstanceType"
      values   = [var.metal_worker_instance_type]
    }
    # RunInstances has no instance-profile resource type. AWS authorizes the
    # role through iam:PassRole; this EC2 condition separately pins the exact
    # profile object named in the request.
    condition {
      test     = "ArnEquals"
      variable = "ec2:InstanceProfile"
      values   = [aws_iam_instance_profile.metal_worker.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CatsIssue"
      values   = ["124"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/CatsPurpose"
      values   = ["temporary-worker-qualification"]
    }
  }

  statement {
    sid       = "TagOnlyDuringLaunch"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*", "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["RunInstances"]
    }
  }

  statement {
    sid       = "OperateOnlyQualificationInstances"
    effect    = "Allow"
    actions   = ["ec2:ModifyInstanceAttribute", "ec2:TerminateInstances"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CatsIssue"
      values   = ["124"]
    }
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/CatsPurpose"
      values   = ["temporary-worker-qualification"]
    }
  }

  statement {
    sid       = "PassOnlyWorkerRoleToEc2"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.metal_worker.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }

  statement {
    sid       = "UseReviewedSsmDocument"
    effect    = "Allow"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}::document/AWS-RunShellScript"]
  }

  statement {
    sid       = "CommandOnlyQualificationInstances"
    effect    = "Allow"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/CatsIssue"
      values   = ["124"]
    }
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/CatsPurpose"
      values   = ["temporary-worker-qualification"]
    }
  }

  statement {
    sid       = "QualificationBundleBucket"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [var.github_qualification_artifact_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["worker/qualification-124/*"]
    }
  }

  statement {
    sid       = "QualificationBundles"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${var.github_qualification_artifact_bucket_arn}/worker/qualification-124/*"]
  }
}

resource "aws_iam_role_policy" "github_qualification_worker" {
  count  = var.github_qualification_worker_enabled ? 1 : 0
  name   = "issue-124-temporary-worker"
  role   = aws_iam_role.github_qualification_worker[0].id
  policy = data.aws_iam_policy_document.github_qualification_worker[0].json
}
