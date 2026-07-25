output "artifact_bucket_name" {
  value = aws_s3_bucket.artifacts.id
}

output "worker_bundle_key" {
  value = aws_s3_object.worker_bundle.key
}

output "association_id" {
  value = aws_ssm_association.worker_deploy.association_id
}

output "runtime_secret_arn" {
  value = aws_secretsmanager_secret.worker_runtime.arn
}
