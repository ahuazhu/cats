variable "cluster_name" {
  type        = string
  description = "EKS cluster name. The infrastructure stack's Pod Identity association references this value."
}

variable "kubernetes_version" {
  type        = string
  description = "EKS control plane version."
  default     = "1.34"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnets carrying the Auto Mode ALB."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets carrying the nodes."
}

variable "public_access_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to reach the public Kubernetes API endpoint."
  default     = ["0.0.0.0/0"]
}

variable "node_pools" {
  type        = list(string)
  description = "Auto Mode node pools to enable."
  default     = ["general-purpose", "system"]
}

variable "cluster_admin_principal_arns" {
  type        = list(string)
  description = <<-EOT
    IAM principals granted AmazonEKSClusterAdminPolicy. The creating principal
    already has admin via bootstrap_cluster_creator_admin_permissions; list any
    additional operator or CI roles here.
  EOT
  default     = []
}

variable "pod_identity_addon_version" {
  type        = string
  description = "eks-pod-identity-agent add-on version. Null selects the default for the cluster version."
  default     = null
}

variable "efs_csi_addon_version" {
  type        = string
  description = "aws-efs-csi-driver add-on version. Null selects the EKS default for the cluster version."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Additional tags."
  default     = {}
}
