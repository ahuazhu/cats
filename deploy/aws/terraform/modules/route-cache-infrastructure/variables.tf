variable "name_prefix" {
  description = "Lowercase prefix used for regional resource names."
  type        = string
  default     = "cats"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name_prefix))
    error_message = "name_prefix must contain 2-31 lowercase letters, digits, or hyphens."
  }
}

variable "environment" {
  description = "Deployment environment, such as production or staging."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.environment))
    error_message = "environment must contain 2-21 lowercase letters, digits, or hyphens."
  }
}

variable "eks_cluster_name" {
  description = "Existing EKS cluster receiving the Gateway Pod Identity association."
  type        = string
}

variable "gateway_service_account_namespace" {
  description = "Kubernetes namespace of the Gateway service account."
  type        = string
  default     = "cats"
}

variable "gateway_service_account_name" {
  description = "Kubernetes service account used by cats-gatewayd."
  type        = string
  default     = "cats-gatewayd"
}

variable "tags" {
  description = "Additional tags applied to AWS resources."
  type        = map(string)
  default     = {}
}
