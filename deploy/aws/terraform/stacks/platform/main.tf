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
  allowed_security_group_ids = [
    module.cluster.cluster_security_group_id,
    aws_security_group.metal_worker.id,
  ]

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
