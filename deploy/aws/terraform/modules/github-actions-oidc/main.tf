# GitHub Actions release identity.
#
# The release workflow pushes the control-plane image to ECR. It authenticates
# by exchanging a GitHub OIDC token for this role, so the repository holds no
# long-lived AWS access key — the same posture the worker uses with its EC2
# instance role.
#
# The trust policy pins both the audience and the subject. Without the subject
# condition any GitHub repository in the world could assume this role.

locals {
  name = "${var.name_prefix}-github-actions-release"

  subjects = length(var.allowed_subjects) > 0 ? var.allowed_subjects : [
    "repo:${var.github_repository}:ref:refs/heads/${var.default_branch}",
    "repo:${var.github_repository}:ref:refs/tags/*",
  ]

  provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.existing_oidc_provider_arn
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.oidc_thumbprints

  tags = merge(var.tags, { Name = "github-actions" })
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.subjects
    }
  }
}

resource "aws_iam_role" "release" {
  name               = local.name
  description        = "GitHub Actions release pipeline for ${var.github_repository}"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

# GetAuthorizationToken has no resource scope; every other action is pinned to
# the Cats repositories.
data "aws_iam_policy_document" "ecr_push" {
  statement {
    sid       = "EcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "EcrPush"
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]

    resources = var.ecr_repository_arns
  }
}

resource "aws_iam_role_policy" "ecr_push" {
  name   = "ecr-push"
  role   = aws_iam_role.release.id
  policy = data.aws_iam_policy_document.ecr_push.json
}
