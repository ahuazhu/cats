locals {
  resource_name = "${var.name_prefix}-${var.environment}-route-grants"
  tags = merge(var.tags, {
    Component   = "endpoint-route-continuity"
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = "Cats"
  })
}

# This table is not route authority. It contains only short-lived grants that
# cats-controld already signed; every Node still verifies the complete grant.
# DynamoDB gives all Gateway replicas a regional, multi-AZ continuity path that
# does not fail with the PostgreSQL-backed control plane.
resource "aws_dynamodb_table" "route_grants" {
  name         = local.resource_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "hostname"

  attribute {
    name = "hostname"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at_unix"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
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

resource "aws_iam_role" "gateway" {
  name               = "${local.resource_name}-gateway"
  description        = "Replicates and reads already-signed Endpoint Route Grants."
  assume_role_policy = data.aws_iam_policy_document.pod_identity_trust.json
  tags               = local.tags
}

data "aws_iam_policy_document" "gateway" {
  statement {
    sid    = "ReplicateSignedRouteGrants"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
    ]
    resources = [aws_dynamodb_table.route_grants.arn]
  }
}

resource "aws_iam_role_policy" "gateway" {
  name   = "replicate-signed-route-grants"
  role   = aws_iam_role.gateway.name
  policy = data.aws_iam_policy_document.gateway.json
}

resource "aws_eks_pod_identity_association" "gateway" {
  cluster_name    = var.eks_cluster_name
  namespace       = var.gateway_service_account_namespace
  service_account = var.gateway_service_account_name
  role_arn        = aws_iam_role.gateway.arn

  tags = local.tags
}
