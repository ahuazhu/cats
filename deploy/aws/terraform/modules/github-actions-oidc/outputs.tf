output "release_role_arn" {
  description = "Set this as the AWS_ROLE_ARN repository variable for the release workflow."
  value       = aws_iam_role.release.arn
}

output "release_role_name" {
  value = aws_iam_role.release.name
}

output "oidc_provider_arn" {
  value = local.provider_arn
}

output "allowed_subjects" {
  value = local.subjects
}
