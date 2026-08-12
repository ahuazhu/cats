variable "expected_account_id" {
  description = "Exact AWS account allowed to contain the qualification cell."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be an explicit 12-digit AWS account ID."
  }
}
variable "aws_region" {
  description = "Exact AWS region for the qualification cell."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "Architecture V2 qualification is pinned to us-east-1."
  }
}

variable "qualification_namespace" {
  description = "Canonical namespace from which every qualification resource name is derived."
  type        = string
  default     = "cats-qualification-v2"

  validation {
    condition     = var.qualification_namespace == "cats-qualification-v2"
    error_message = "qualification_namespace must be cats-qualification-v2."
  }
}

variable "qualification_cell_id" {
  description = "Stable identity of this qualification cell."
  type        = string
  default     = "qcell-use1-v1"

  validation {
    condition     = var.qualification_cell_id == "qcell-use1-v1"
    error_message = "qualification_cell_id must be qcell-use1-v1 for the initial cell."
  }
}

variable "bootstrap_principal_arn" {
  description = "Exact reviewed account-level principal allowed to assume the state-only role."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:(user|role)/[A-Za-z0-9+=,.@_/-]+$", var.bootstrap_principal_arn))
    error_message = "bootstrap_principal_arn must be an explicit IAM user or role ARN."
  }
}
