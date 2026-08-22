output "namespace" {
  description = "Namespace containing the Cats application."
  value       = kubernetes_namespace_v1.cats.metadata[0].name
}

output "control_plane_service" {
  description = "Cluster-local cats-controld service name."
  value       = "${kubernetes_service_v1.control_plane.metadata[0].name}.${var.namespace}.svc"
}

output "ingress_name" {
  description = "Public ingress name, or null when public ingress is disabled."
  value       = local.effective_public_ingress ? kubernetes_ingress_v1.public[0].metadata[0].name : null
}

output "ingress_load_balancer_hostname" {
  description = "Hostname of the load balancer EKS provisioned for the public ingress, or null when public ingress is disabled."
  value = try(
    kubernetes_ingress_v1.public[0].status[0].load_balancer[0].ingress[0].hostname,
    null,
  )
}
