data "aws_partition" "current" {}
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

module "cats_kubernetes" {
  source = "../../modules/cats-kubernetes"

  namespace                                     = "cats"
  control_plane_image                           = var.control_plane_image
  control_plane_replicas                        = var.control_plane_replicas
  gateway_image                                 = var.gateway_image
  gateway_replicas                              = var.gateway_replicas
  object_write_gateway_image                    = var.object_write_gateway_image
  object_write_gateway_replicas                 = var.object_write_gateway_replicas
  object_write_gateway_tls_secret_name          = var.object_write_gateway_tls_secret_name
  object_write_gateway_nlb_security_group_id    = var.object_write_gateway_nlb_security_group_id
  object_write_gateway_private_subnet_ids       = var.private_subnet_ids
  object_write_spool_file_system_id             = var.object_write_spool_file_system_id
  object_write_spool_access_point_id            = var.object_write_spool_access_point_id
  object_write_provider_partition               = var.expected_aws_partition
  object_write_provider_account_id              = var.expected_account_id
  maintenance_mode                              = var.maintenance_mode
  enable_public_ingress                         = var.enable_public_ingress
  route_v2_control_artifact_secret_name         = var.route_v2_control_artifact_secret_name
  route_v2_control_artifact_signer_revision     = var.route_v2_control_artifact_signer_revision
  route_v2_control_artifact_secret_sha256       = var.route_v2_control_artifact_secret_sha256
  route_v2_gateway_artifact_secret_name         = var.route_v2_gateway_artifact_secret_name
  runtime_secret_data                           = var.runtime_secret_data
  route_grant_private_key_pem                   = var.route_grant_private_key_pem
  route_grant_public_key_pem                    = var.route_grant_public_key_pem
  runtime_provisioner_trust_bundle_json         = var.runtime_provisioner_trust_bundle_json
  production_cutover_operator_trust_bundle_json = var.production_cutover_operator_trust_bundle_json
  storage_postgres_url                          = var.storage_postgres_url
  control_postgres_schema                       = var.control_postgres_schema
  storage_postgres_session_setup                = var.storage_postgres_session_setup
  chunkstore_bucket_name                        = var.chunkstore_bucket_name
  chunkstore_region                             = var.aws_region
  chunkstore_prefix                             = var.chunkstore_prefix
  usage_postgres_url                            = var.usage_postgres_url
  usage_postgres_schema                         = var.usage_postgres_schema
  usage_postgres_workers                        = var.usage_postgres_workers
  usage_delivery_adapter                        = var.usage_delivery_adapter
  usage_aws_region                              = var.usage_aws_region
  usage_kinesis_stream                          = var.usage_kinesis_stream
  usage_archive_bucket                          = var.usage_archive_bucket
  usage_checkpoint_table                        = var.usage_checkpoint_table
  stripe_enabled                                = var.stripe_enabled
  stripe_secret_key                             = var.stripe_secret_key
  stripe_webhook_secret                         = var.stripe_webhook_secret
  stripe_topup_price_ids                        = var.stripe_topup_price_ids
  stripe_livemode                               = var.stripe_livemode
  rds_ca_pem                                    = var.rds_ca_pem

  # In-cluster reconciliation of the database credential (ADR-0029, #77). The
  # Pod Identity association it needs lives in the infrastructure state.
  credential_refresher_image      = var.credential_refresher_image
  credential_refresher_mode       = var.credential_refresher_mode
  database_master_user_secret_arn = var.database_master_user_secret_arn
  auto_warm_after_seconds         = var.auto_warm_after_seconds
  auto_cold_after_seconds         = var.auto_cold_after_seconds
  acm_certificate_arn             = var.acm_certificate_arn
  public_subnet_ids               = var.public_subnet_ids
  control_plane_hosts             = var.control_plane_hosts
  endpoint_wildcard_host          = var.endpoint_wildcard_host

  depends_on = [terraform_data.aws_target]
}

# Public DNS.
#
# The hosted zone belongs to the platform state, but the load balancer only
# exists once this stack's ingress reconciles, so the alias records that join
# them belong here. The account this replaces had these records created by hand,
# which is why a rebuild had no way to know they were needed.
#
# Set route53_zone_id to enable; leave it null when a different system owns DNS.
locals {
  # Maintenance is a reviewed Terraform transition: the same saved plan that
  # removes the public Ingress also removes its DNS aliases.  Keeping this in
  # state avoids an emergency kubectl edit becoming an unrecorded drift path.
  manage_dns = var.route53_zone_id != null && var.enable_public_ingress && !var.maintenance_mode

  dns_hosts = setunion(toset(var.control_plane_hosts), toset([var.endpoint_wildcard_host]))
}

# Located by the tag EKS puts on the load balancer it provisions, because the
# generated name is not stable across a recreate.
data "aws_lb" "public" {
  count = local.manage_dns ? 1 : 0

  tags = {
    "ingress.eks.amazonaws.com/stack" = "${module.cats_kubernetes.namespace}/${module.cats_kubernetes.ingress_name}"
  }

  depends_on = [module.cats_kubernetes]
}

resource "aws_route53_record" "public" {
  for_each = local.manage_dns ? local.dns_hosts : toset([])

  zone_id = var.route53_zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = data.aws_lb.public[0].dns_name
    zone_id                = data.aws_lb.public[0].zone_id
    evaluate_target_health = true
  }
}

# Stable private certificate authority name for the TLS pass-through NLB. The
# Service status supplies only the generated ELB hostname; a private CNAME
# keeps the serverAuth leaf SAN release-bound and deterministic.
resource "aws_route53_record" "object_write_gateway" {
  zone_id = var.object_write_gateway_private_zone_id
  name    = var.object_write_gateway_private_dns_name
  type    = "CNAME"
  ttl     = 60
  records = [module.cats_kubernetes.object_write_gateway_load_balancer_hostname]
}
