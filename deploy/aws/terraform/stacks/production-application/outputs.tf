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
