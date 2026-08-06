output "table_name" {
  description = "DynamoDB table carrying short-lived signed Route Grants."
  value       = aws_dynamodb_table.route_grants.name
}

output "table_arn" {
  description = "ARN of the shared signed Route Grant table."
  value       = aws_dynamodb_table.route_grants.arn
}

output "gateway_role_arn" {
  description = "Pod Identity role assumed by cats-gatewayd."
  value       = aws_iam_role.gateway.arn
}

output "pod_identity_association_id" {
  description = "Gateway Pod Identity association ID."
  value       = aws_eks_pod_identity_association.gateway.association_id
}
