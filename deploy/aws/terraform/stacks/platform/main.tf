# Cats platform: the network, cluster, database, DNS and release identity that
# every other stack treats as given.
#
# The previous account never had this stack. Its VPC, EKS cluster, RDS instance
# and ACM certificate were created by hand and only ever referenced as
# migration inputs, so ADR-0012's "Terraform is the authoritative change path"
# did not hold for the resources hardest to rebuild. This state closes that gap
# from the first apply.
#
# Apply order across the states:
#   bootstrap -> platform -> production-infrastructure -> production-application
#
# `bootstrap` comes first and keeps local state, because it creates the S3
# bucket every later state — including this one — stores its state in.

module "network" {
  source = "../../modules/platform-network"

  name_prefix             = var.name_prefix
  environment             = var.environment
  aws_region              = var.aws_region
  vpc_cidr                = var.vpc_cidr
  availability_zone_count = var.availability_zone_count
  one_nat_gateway_per_az  = var.one_nat_gateway_per_az
  tags                    = var.tags
}

module "cluster" {
  source = "../../modules/platform-cluster"

  cluster_name                 = var.cluster_name
  kubernetes_version           = var.kubernetes_version
  public_subnet_ids            = module.network.public_subnet_ids
  private_subnet_ids           = module.network.private_subnet_ids
  public_access_cidrs          = var.cluster_public_access_cidrs
  cluster_admin_principal_arns = var.cluster_admin_principal_arns
  tags                         = var.tags
}

module "database" {
  source = "../../modules/platform-database"

  name_prefix        = var.name_prefix
  environment        = var.environment
  vpc_id             = module.network.vpc_id
  private_subnet_ids = module.network.private_subnet_ids

  # Both sides of the EKS/metal boundary reach this instance.
  allowed_security_group_ids = {
    cluster      = module.cluster.cluster_security_group_id
    metal_worker = aws_security_group.metal_worker.id
  }

  engine_version        = var.database_engine_version
  instance_class        = var.database_instance_class
  allocated_storage     = var.database_allocated_storage
  multi_az              = var.database_multi_az
  backup_retention_days = var.database_backup_retention_days
  deletion_protection   = var.database_deletion_protection
  skip_final_snapshot   = var.database_skip_final_snapshot
  tags                  = var.tags
}

module "dns" {
  source = "../../modules/platform-dns"

  domain_name         = var.domain_name
  environment         = var.environment
  wait_for_validation = var.wait_for_certificate_validation
  tags                = var.tags
}

module "github_release" {
  source = "../../modules/github-actions-oidc"

  name_prefix          = var.name_prefix
  github_repository    = var.github_repository
  default_branch       = var.github_default_branch
  create_oidc_provider = var.create_github_oidc_provider
  ecr_repository_arns  = [aws_ecr_repository.control_plane.arn]
  tags                 = var.tags
}

# Bare-metal workers.
#
# The instances themselves are not created here: they are long-lived, hand-sized
# capacity that the infrastructure stack configures by instance id. What is
# managed here is the network position they must occupy — cats-noded listens on
# 7301 and is reached by cats-gatewayd and cats-controld from inside the
# cluster. Nothing else may reach it.
resource "aws_security_group" "metal_worker" {
  name        = "${var.name_prefix}-${var.environment}-metal-worker"
  description = "Cats bare-metal worker"
  vpc_id      = module.network.vpc_id

  tags = merge(var.tags, { Name = "${var.name_prefix}-${var.environment}-metal-worker" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "metal_worker_node_agent" {
  security_group_id            = aws_security_group.metal_worker.id
  referenced_security_group_id = module.cluster.cluster_security_group_id
  from_port                    = 7301
  to_port                      = 7301
  ip_protocol                  = "tcp"
  description                  = "cats-noded from the cluster"
}

# S3, RDS, SSM and ECR are all reached outbound; the guest tap NAT also egresses
# through here.
resource "aws_vpc_security_group_egress_rule" "metal_worker_all" {
  security_group_id = aws_security_group.metal_worker.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "All outbound"
}

resource "aws_ecr_repository" "control_plane" {
  name                 = var.ecr_repository_name
  image_tag_mutability = var.ecr_image_tag_mutability
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = merge(var.tags, { Name = var.ecr_repository_name })
}

# Deployments pin digests, so untagged layers left by a rebuild are pure cost.
resource "aws_ecr_lifecycle_policy" "control_plane" {
  repository = aws_ecr_repository.control_plane.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 14 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the most recent ${var.ecr_keep_last_images} tagged images"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "imageCountMoreThan"
          countNumber    = var.ecr_keep_last_images
        }
        action = { type = "expire" }
      },
    ]
  })
}

# ChunkStore.
#
# The durable truth for every Cat's disks: immutable content-addressed objects,
# with PostgreSQL holding the roots, leases and fencing epochs that point at
# them (ADR-0003). No Terraform state owned this bucket in the account being
# replaced -- it was created by hand, so a rebuild had no way to learn that the
# workers depend on it.
#
# Versioning matches the previous bucket. The objects are immutable by
# construction, so this is purely a guard against an erroneous delete.
resource "aws_s3_bucket" "chunkstore" {
  bucket        = var.chunkstore_bucket_name
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(var.tags, { Name = var.chunkstore_bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "chunkstore" {
  bucket = aws_s3_bucket.chunkstore.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "chunkstore" {
  bucket = aws_s3_bucket.chunkstore.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "chunkstore" {
  bucket = aws_s3_bucket.chunkstore.id

  versioning_configuration {
    status = var.chunkstore_versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "chunkstore" {
  bucket = aws_s3_bucket.chunkstore.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "chunkstore_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.chunkstore.arn,
      "${aws_s3_bucket.chunkstore.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "chunkstore" {
  bucket = aws_s3_bucket.chunkstore.id
  policy = data.aws_iam_policy_document.chunkstore_tls_only.json
}

# Bare-metal worker instance identity.
#
# The S3 adapter uses these instance credentials and refreshes them, so no
# long-lived AWS key ever reaches worker.env. The infrastructure stack attaches
# SSM and artifact-bucket access to this same role; what it cannot know about
# is the ChunkStore, so that grant lives here with the bucket.
data "aws_iam_policy_document" "metal_worker_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "metal_worker" {
  name               = "${var.name_prefix}-${var.environment}-metal-worker"
  assume_role_policy = data.aws_iam_policy_document.metal_worker_assume.json

  tags = var.tags
}

resource "aws_iam_instance_profile" "metal_worker" {
  name = aws_iam_role.metal_worker.name
  role = aws_iam_role.metal_worker.name

  tags = var.tags
}

data "aws_iam_policy_document" "metal_worker_chunkstore" {
  statement {
    sid       = "ListChunkStore"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.chunkstore.arn]
  }

  statement {
    sid    = "ReadWriteChunkStore"
    effect = "Allow"

    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
    ]

    resources = ["${aws_s3_bucket.chunkstore.arn}/*"]
  }
}

resource "aws_iam_role_policy" "metal_worker_chunkstore" {
  name   = "chunkstore"
  role   = aws_iam_role.metal_worker.id
  policy = data.aws_iam_policy_document.metal_worker_chunkstore.json
}
