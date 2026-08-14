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

  cluster_name        = var.cluster_name
  kubernetes_version  = var.kubernetes_version
  public_subnet_ids   = module.network.public_subnet_ids
  private_subnet_ids  = module.network.private_subnet_ids
  public_access_cidrs = var.cluster_public_access_cidrs
  cluster_admin_principal_arns = distinct(concat(
    var.cluster_admin_principal_arns,
    [module.github_release.release_role_arn],
  ))
  tags = var.tags
}

# The platform owns one alert topic and exposes its exact ARN to the separate
# production-infrastructure state. That stack accepts the ARN through one
# explicit variable rather than duplicating the topic or silently using an
# empty action list.
#
# Not encrypted: the alarm text carries no secret, and the AWS-managed SNS key
# cannot be used, because CloudWatch cannot be granted access to it.
locals {
  alert_topic_name = "${var.name_prefix}-${var.environment}-alerts"
  expected_alert_topic_arn = join(":", [
    "arn",
    var.expected_aws_partition,
    "sns",
    var.aws_region,
    var.expected_account_id,
    local.alert_topic_name,
  ])
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "terraform_data" "aws_target" {
  input = {
    account_id = data.aws_caller_identity.current.account_id
    partition  = data.aws_partition.current.partition
    region     = data.aws_region.current.region
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
  }
}

resource "aws_sns_topic" "alerts" {
  name = local.alert_topic_name

  tags = merge(var.tags, { Name = local.alert_topic_name })

  depends_on = [terraform_data.aws_target]

  lifecycle {
    postcondition {
      condition     = self.arn == local.expected_alert_topic_arn
      error_message = "Created alert topic ARN does not match the exact expected AWS target."
    }
  }
}

# An email subscription stays "pending confirmation" until the recipient clicks
# the link AWS sends. Terraform reports it as created either way, so confirm out
# of band before treating the alarm as wired up.
resource "aws_sns_topic_subscription" "alert_email" {
  for_each = nonsensitive(toset(keys(var.alert_email_recipients)))

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email_recipients[each.key]
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
  log_retention_days    = var.database_log_retention_days
  alarm_action_arns     = [aws_sns_topic.alerts.arn]
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

  name_prefix               = var.name_prefix
  github_repository         = var.github_repository
  github_subject_repository = var.github_subject_repository
  default_branch            = var.github_default_branch
  create_oidc_provider      = var.create_github_oidc_provider
  ecr_repository_arns       = [aws_ecr_repository.control_plane.arn]
  tags                      = var.tags
}

# The same branch-pinned OIDC identity deploys the reviewed application state
# after main CI succeeds. Its AWS permissions are intentionally limited to the
# application state, one EKS cluster, the public load balancer lookup and this
# hosted zone. Kubernetes authorization is granted above through the EKS access
# entry rather than an aws-auth ConfigMap.
data "aws_partition" "current" {}

data "aws_iam_policy_document" "github_application_deploy" {
  statement {
    sid       = "ApplicationStateBucket"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [var.github_actions_application_state_bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        var.github_actions_application_state_key,
        "${var.github_actions_application_state_key}.tflock",
      ]
    }
  }

  statement {
    sid       = "ApplicationState"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${var.github_actions_application_state_bucket_arn}/${var.github_actions_application_state_key}"]
  }

  statement {
    sid       = "ApplicationStateLock"
    effect    = "Allow"
    actions   = ["s3:DeleteObject", "s3:GetObject", "s3:PutObject"]
    resources = ["${var.github_actions_application_state_bucket_arn}/${var.github_actions_application_state_key}.tflock"]
  }

  statement {
    sid       = "DescribeEksCluster"
    effect    = "Allow"
    actions   = ["eks:DescribeCluster"]
    resources = [module.cluster.cluster_arn]
  }

  # The application stack locates the EKS Auto Mode ALB by tag. Describe
  # actions do not support useful resource scoping.
  statement {
    sid    = "ReadApplicationLoadBalancer"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTags",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ManageApplicationDns"
    effect = "Allow"
    actions = [
      "route53:ChangeResourceRecordSets",
      "route53:GetHostedZone",
      "route53:ListResourceRecordSets",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:route53:::hostedzone/${module.dns.zone_id}",
    ]
  }

  # The deployment composes the control plane's DSNs from the RDS managed
  # master secret rather than carrying forward whatever password the live
  # Kubernetes Secret already held. Without this it would keep reproducing a
  # copy, and a rotation would again be discovered by replacing the Pod.
  # Scoped to that one secret.
  statement {
    sid       = "ReadDatabaseMasterUserSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [module.database.master_user_secret_arn]
  }

}

resource "aws_iam_role_policy" "github_application_deploy" {
  name   = "application-deploy"
  role   = module.github_release.release_role_name
  policy = data.aws_iam_policy_document.github_application_deploy.json
}

# Bare-metal workers: the network position they occupy. The signed Runtime
# listener on 7301 and independent Route v2 mTLS listener on 7444 are reachable
# only from the cluster security group. The instances themselves are declared
# further down, and the infrastructure stack installs onto them by id.
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

# Route v2 is an independent mTLS listener. Keeping its rule separate from the
# signed Runtime listener prevents a future port-range edit from silently
# widening either authority boundary.
resource "aws_vpc_security_group_ingress_rule" "metal_worker_route_v2" {
  security_group_id            = aws_security_group.metal_worker.id
  referenced_security_group_id = module.cluster.cluster_security_group_id
  from_port                    = 7444
  to_port                      = 7444
  ip_protocol                  = "tcp"
  description                  = "Route v2 Gateway to Node mTLS"
}

# Workers sit in private subnets with no public address, so the operator path in
# is an EC2 Instance Connect Endpoint placed in this same group. The rule is
# self-referencing rather than a CIDR: only something already inside the group
# can open a shell.
resource "aws_vpc_security_group_ingress_rule" "metal_worker_ssh" {
  count = var.metal_worker_ssh_from_instance_connect ? 1 : 0

  security_group_id            = aws_security_group.metal_worker.id
  referenced_security_group_id = aws_security_group.metal_worker.id
  from_port                    = 22
  to_port                      = 22
  ip_protocol                  = "tcp"
  description                  = "sshd from the EC2 Instance Connect Endpoint"
}

# S3, RDS, SSM and ECR are all reached outbound; the guest tap NAT also egresses
# through here.
resource "aws_vpc_security_group_egress_rule" "metal_worker_all" {
  security_group_id = aws_security_group.metal_worker.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "All outbound"
}

# Host fencing may replace a worker's primary ENI groups with this exact empty
# boundary, but the group is never the HostFence authority: the authoritative
# proof is the ObjectWrite Gateway's closed accepted-PUT prefix. Keeping this
# as a dedicated, rule-free group makes the secondary observation exact and
# prevents a broad account-wide network mutation.
resource "aws_security_group" "metal_worker_fence" {
  name                   = "${var.name_prefix}-${var.environment}-metal-worker-fence"
  description            = "Deny-all secondary quarantine boundary for fenced Cats workers"
  vpc_id                 = module.network.vpc_id
  revoke_rules_on_delete = true

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.environment}-metal-worker-fence"
    Authority = "secondary-only"
  })

  lifecycle {
    create_before_destroy = true
  }
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

# Bare-metal worker instance identity. Workers retain direct immutable-object
# reads, but no direct ChunkStore write or delete authority. Every accepted PUT
# passes through the repository-owned ObjectWrite Gateway so a Host-scoped
# principal can be atomically closed and its accepted sequence prefix drained.
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

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        var.chunkstore_prefix,
        "${var.chunkstore_prefix}/*",
      ]
    }
  }

  statement {
    sid     = "ReadChunkStore"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}/*",
    ]
  }

  # An explicit identity-policy deny prevents a later broad attachment from
  # silently restoring direct writes to blockd. The Gateway role below is a
  # different principal and is unaffected.
  statement {
    sid    = "DenyDirectChunkStoreMutation"
    effect = "Deny"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:PutObject",
    ]
    resources = [
      "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}/*",
    ]
  }
}

resource "aws_iam_role_policy" "metal_worker_chunkstore" {
  name   = "chunkstore"
  role   = aws_iam_role.metal_worker.id
  policy = data.aws_iam_policy_document.metal_worker_chunkstore.json
}

# The ObjectWrite Gateway is the sole principal permitted to publish new
# ChunkStore objects. Its PostgreSQL authority issues and closes Host-scoped
# accepted request sequences; this AWS role only performs the resulting exact
# immutable PUT and visibility discovery. It cannot delete objects or mutate
# compute/network state.
data "aws_iam_policy_document" "object_write_gateway_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "object_write_gateway" {
  name               = "${var.name_prefix}-${var.environment}-object-write-gateway"
  description        = "Publishes only DB-accepted immutable Cats objects and proves their visibility"
  assume_role_policy = data.aws_iam_policy_document.object_write_gateway_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "object_write_gateway_chunkstore" {
  statement {
    sid       = "DiscoverExactChunkStorePrefix"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.chunkstore.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        var.chunkstore_prefix,
        "${var.chunkstore_prefix}/*",
      ]
    }
  }

  statement {
    sid    = "PublishAndVerifyAcceptedObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectAttributes",
      "s3:PutObject",
    ]
    resources = [
      "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}/*",
    ]
  }
}

resource "aws_iam_role_policy" "object_write_gateway_chunkstore" {
  name   = "accepted-object-publish"
  role   = aws_iam_role.object_write_gateway.id
  policy = data.aws_iam_policy_document.object_write_gateway_chunkstore.json
}

resource "aws_eks_pod_identity_association" "object_write_gateway" {
  cluster_name    = module.cluster.cluster_name
  namespace       = var.object_write_gateway_namespace
  service_account = var.object_write_gateway_service_account
  role_arn        = aws_iam_role.object_write_gateway.arn

  tags = var.tags
}

# HostFence provider permissions are deliberately separate from the object
# writer. Read-only Describe calls must be global because EC2 does not support
# resource scoping for them; every mutation is limited to the immutable worker
# instance IDs and primary ENIs declared in this same state. There is no Start,
# IAM, credential, tag, or account-wide mutation permission.
data "aws_iam_policy_document" "host_fence_provider_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "host_fence_provider" {
  name               = "${var.name_prefix}-${var.environment}-host-fence-provider"
  description        = "Observes and secondarily isolates only declared Cats bare-metal workers"
  assume_role_policy = data.aws_iam_policy_document.host_fence_provider_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "host_fence_provider" {
  statement {
    sid       = "RediscoverFencePostconditions"
    effect    = "Allow"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces"]
    resources = ["*"]
  }

  statement {
    sid     = "StopOnlyDeclaredWorkers"
    effect  = "Allow"
    actions = ["ec2:StopInstances"]
    resources = [
      for worker in aws_instance.metal_worker :
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.expected_account_id}:instance/${worker.id}"
    ]
  }

  statement {
    sid     = "QuarantineOnlyDeclaredWorkerPrimaryEnis"
    effect  = "Allow"
    actions = ["ec2:ModifyNetworkInterfaceAttribute"]
    resources = [
      for worker in aws_instance.metal_worker :
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.expected_account_id}:network-interface/${worker.primary_network_interface_id}"
    ]
  }

  # The Control Plane invokes HostFence but is not the ObjectWrite Gateway.
  # Keep this deny explicit so a future broad S3 attachment cannot collapse
  # the independently fenced writer boundary back into cats-controld.
  statement {
    sid    = "DenyControlPlaneChunkStoreMutation"
    effect = "Deny"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:PutObject",
    ]
    resources = [
      "${aws_s3_bucket.chunkstore.arn}/${var.chunkstore_prefix}/*",
    ]
  }
}

resource "aws_iam_role_policy" "host_fence_provider" {
  name   = "exact-worker-secondary-isolation"
  role   = aws_iam_role.host_fence_provider.id
  policy = data.aws_iam_policy_document.host_fence_provider.json
}

resource "aws_eks_pod_identity_association" "host_fence_provider" {
  cluster_name    = module.cluster.cluster_name
  namespace       = var.host_fence_provider_namespace
  service_account = var.host_fence_provider_service_account
  role_arn        = aws_iam_role.host_fence_provider.arn

  tags = var.tags
}

# The bare-metal worker itself.
#
# Long-lived capacity, and therefore Terraform's to own. Leaving it as a hand
# made instance is precisely the pattern this migration kept paying for: the
# DNS records, the ChunkStore bucket, the worker role and the instance-store
# mount were all created by hand in the previous account and all four were
# invisible to a rebuild.
#
# Instance storage is not declared here. c5d exposes it unconditionally and
# install-worker.sh mounts it at /var/lib/cats; it is ephemeral cache in front
# of the S3 ChunkStore, so a stop/start losing it is by design.
resource "aws_instance" "metal_worker" {
  for_each = var.metal_workers

  ami                    = var.metal_worker_ami
  instance_type          = var.metal_worker_instance_type
  subnet_id              = module.network.private_subnet_ids[each.value.subnet_index]
  vpc_security_group_ids = [aws_security_group.metal_worker.id]
  iam_instance_profile   = aws_iam_instance_profile.metal_worker.name

  instance_initiated_shutdown_behavior = "stop"

  root_block_device {
    volume_size           = var.metal_worker_root_volume_gib
    volume_type           = "gp3"
    encrypted             = each.value.root_volume_encrypted
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tags = merge(var.tags, {
    Name    = "cats-${each.key}"
    Project = "Cats"
  })

  lifecycle {
    # user_data only runs on first boot, and rewriting it would replace a
    # worker that is serving Cats. The AMI is pinned rather than tracked, for
    # the same reason: a new Canonical publication must not recycle the fleet.
    #
    # Root encryption is intentionally not ignored. The normal production map
    # records metal-2's legacy unencrypted root, so it produces no replacement;
    # changing that one value to true makes the maintenance-window replacement
    # visible in the exact reviewed saved plan. prevent_destroy cannot be
    # conditional in Terraform, so ADR-0012's saved-plan review is the gate.
    ignore_changes = [user_data, user_data_base64, ami]

    precondition {
      condition     = each.value.subnet_index < length(module.network.private_subnet_ids)
      error_message = "metal worker subnet_index must select a configured private subnet."
    }
  }
}

# Preserve the exact imported production identities while replacing positional
# count addresses with stable names. Remote state has index 0 = cats-metal-2
# and index 1 = cats-metal-1; reversing these moves would target the wrong Host.
moved {
  from = aws_instance.metal_worker[0]
  to   = aws_instance.metal_worker["metal-2"]
}

moved {
  from = aws_instance.metal_worker[1]
  to   = aws_instance.metal_worker["metal-1"]
}

# Operator access to a worker that has no public address.
resource "aws_ec2_instance_connect_endpoint" "workers" {
  count = var.metal_worker_ssh_from_instance_connect ? 1 : 0

  subnet_id          = module.network.private_subnet_ids[0]
  security_group_ids = [aws_security_group.metal_worker.id]
  preserve_client_ip = false

  tags = merge(var.tags, { Name = "cats-eic" })
}
