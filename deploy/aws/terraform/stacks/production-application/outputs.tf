output "namespace" {
  value = module.cats_kubernetes.namespace
}

output "control_plane_service" {
  value = module.cats_kubernetes.control_plane_service
}

output "control_plane_route_v2_service" {
  value = module.cats_kubernetes.control_plane_route_v2_service
}

output "gateway_service" {
  value = module.cats_kubernetes.gateway_service
}

output "object_write_gateway_url" {
  description = "Set on Nodes as CATS_OBJECT_WRITE_GATEWAY_URL; HTTPS hostname is verified against the node-server CA."
  value       = "https://${var.object_write_gateway_private_dns_name}"
}

output "object_write_gateway_ca_artifact" {
  description = "Existing public CA bundle installed on every Node as CATS_OBJECT_WRITE_GATEWAY_CA_FILE."
  value       = "node-server-ca-bundle.pem"
}

output "ingress_name" {
  value = module.cats_kubernetes.ingress_name
}

output "public_dns_records" {
  description = "Public hostnames aliased to the ingress load balancer."
  value       = sort([for r in aws_route53_record.public : r.fqdn])
}

output "maintenance_mode" {
  description = "Whether Terraform has closed public ingress and scaled cats-controld to zero."
  value       = var.maintenance_mode
}
