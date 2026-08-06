locals {
  build_host_manifest = {
    schema_version            = 1
    contract_id               = "qualification-h2-build-host-create-v1"
    environment               = "qualification"
    environment_is_production = false
    account_id                = var.expected_account_id
    region                    = var.aws_region
    namespace                 = var.qualification_namespace
    cell_id                   = var.qualification_cell_id
    required_tags             = local.required_tags
    state_key                 = "architecture-v2/h2-build-host/terraform.tfstate"
    authority = {
      formation_mode           = var.formation_mode
      formation_principal_arn  = var.formation_principal_arn
      reconcile_role_arn       = local.reconcile_role_arn
      reconcile_boundary_arn   = local.deployer_boundary_arn
      post_apply_gate          = "assumed-role-no-op-plan"
      privilege_policy_changes = "formation-review-required"
    }
    canonical_ami = local.canonical_ami
    host = {
      instance_type          = local.instance_type
      availability_zone_id   = local.availability_zone_id
      public_ip_allowed      = false
      inbound_allowed        = false
      administration         = "ssm-only"
      imdsv2_required        = true
      termination_protection = true
      root_volume            = local.root_volume
      root_volume_kms_alias  = local.volume_kms_alias
    }
    network = {
      ownership            = "qualification-only"
      production_vpc_reuse = false
      vpc_cidr             = local.vpc_cidr
      public_subnet_cidr   = local.public_subnet_cidr
      private_subnet_cidr  = local.private_subnet_cidr
      internet_egress      = "nat-tls-only"
      time_sync            = "169.254.169.123/32 udp/123"
    }
    artifacts = {
      bucket                 = local.artifact_bucket_name
      kms_alias              = local.artifact_kms_alias
      prefixes               = local.artifact_prefixes
      append_only            = true
      encryption             = "aws:kms"
      read_allowed           = false
      maximum_object_bytes   = 5368709120
      publication_receipt_v1 = true
    }
    bootstrap = {
      mode                  = "asynchronous-systemd"
      management_ready_gate = "ssm-online"
      build_ready_path      = "/var/lib/cats-build/readiness-v1.json"
      bootstrap_sha256      = local.bootstrap_identity.bootstrap_sha256
      toolchain_lock_sha256 = local.bootstrap_identity.toolchain_lock_sha256
      components_sha256     = local.bootstrap_components_sha256
      payload_sha256        = local.bootstrap_identity.bootstrap_payload_sha256
      apt_snapshot_id       = local.bootstrap_identity.apt_snapshot_id
    }
    source_policy = {
      repository_identity          = "https://github.com/ahuazhu/cats.git"
      delivery_mode                = "controller-content-addressed-git-bundle-v1"
      source_bucket                = local.source_bucket_name
      source_kms_alias             = local.source_kms_alias
      manifest_prefix              = "source/manifests/sha256/"
      bundle_prefix                = "source/bundles/sha256/"
      exact_commit_sha_required    = true
      manifest_digest_required     = true
      bundle_digest_required       = true
      branch_or_tag_allowed        = false
      dirty_worktree_allowed       = false
      build_host_github_credential = false
      build_host_source_write      = false
      submodules_allowed           = false
      gitlinks_allowed             = false
      git_lfs_allowed              = false
      source_owner                 = "root"
      build_target_owner           = "cats-build-per-job"
    }
  }
}

output "qualification_build_host_manifest" {
  description = "Deterministic H2 contract reviewed before the saved plan may be applied."
  value       = local.build_host_manifest
}

output "build_host_instance_id" {
  description = "SSM target after the reviewed plan is applied."
  value       = aws_instance.build.id
}

output "artifact_bucket_name" {
  value = aws_s3_bucket.artifacts.id
}

output "build_readiness_path" {
  value = local.build_host_manifest.bootstrap.build_ready_path
}

output "source_bucket_name" {
  description = "Controller publication bucket for content-addressed source bundles."
  value       = aws_s3_bucket.source.id
}

output "source_kms_alias_arn" {
  description = "Deterministic dedicated KMS alias used by controller source uploads."
  value       = local.source_kms_alias_arn
}

output "cloud_init_base64_length" {
  description = "Encoded gzip user-data length; must remain at or below the conservative 21,844-character gate."
  value       = length(local.cloud_init_base64)
}
