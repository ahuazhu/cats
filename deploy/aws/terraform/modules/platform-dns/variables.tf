variable "domain_name" {
  type        = string
  description = "Apex domain, e.g. cats.run. The certificate also covers *.<domain>."
}

variable "environment" {
  type        = string
  description = "Deployment environment name."
}

variable "wait_for_validation" {
  type        = bool
  description = <<-EOT
    Block the apply until ACM issues the certificate. Leave false until the
    registrar's name servers point at this zone, otherwise the apply waits for
    a record the world cannot resolve yet.
  EOT
  default     = false
}

variable "validation_timeout" {
  type        = string
  description = "How long to wait for issuance when wait_for_validation is true."
  default     = "30m"
}

variable "tags" {
  type        = map(string)
  description = "Additional tags."
  default     = {}
}
