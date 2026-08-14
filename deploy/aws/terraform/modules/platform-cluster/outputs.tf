output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "cluster_arn" {
  value = aws_eks_cluster.this.arn
}

output "cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority_data" {
  value = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_version" {
  value = aws_eks_cluster.this.version
}

# Auto Mode nodes attach to this security group; RDS and any bare-metal worker
# ingress rule should reference it rather than a CIDR.
output "cluster_security_group_id" {
  value = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
}

output "node_role_arn" {
  value = aws_iam_role.node.arn
}

output "node_role_name" {
  description = "Exact EKS Auto Mode node role name for resource-scoped client policies."
  value       = aws_iam_role.node.name
}

output "oidc_issuer_url" {
  value = aws_eks_cluster.this.identity[0].oidc[0].issuer
}
