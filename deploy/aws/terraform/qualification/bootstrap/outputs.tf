output "qualification_manifest_seed" {
  description = "Deterministic identity seed extended by G1-G3 environment manifests."
  value       = local.manifest_seed
}

output "qualification_manifest_seed_json" {
  description = "Canonicalizable JSON form of the deterministic manifest seed."
  value       = jsonencode(local.manifest_seed)
}

output "state_bucket_name" {
  value = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  value = aws_kms_key.state.arn
}

output "state_role_arn" {
  value = aws_iam_role.state.arn
}

output "backend_hcl" {
  description = "Backend settings for later qualification states; choose a key below state_key_prefix."
  value = {
    bucket       = aws_s3_bucket.state.id
    region       = var.aws_region
    encrypt      = true
    kms_key_id   = aws_kms_key.state.arn
    use_lockfile = true
    assume_role = {
      role_arn = aws_iam_role.state.arn
    }
  }
}
