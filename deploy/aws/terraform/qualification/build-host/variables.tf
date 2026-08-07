variable "expected_account_id" {
  description = "Exact AWS account allowed to contain the qualification build host."
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
  description = "Canonical namespace established by the G0 boundary."
  type        = string
  default     = "cats-qualification-v2"

  validation {
    condition     = var.qualification_namespace == "cats-qualification-v2"
    error_message = "qualification_namespace must be cats-qualification-v2."
  }
}

variable "qualification_cell_id" {
  description = "Stable identity established by the G0 boundary."
  type        = string
  default     = "qcell-use1-v1"

  validation {
    condition     = var.qualification_cell_id == "qcell-use1-v1"
    error_message = "qualification_cell_id must be qcell-use1-v1."
  }
}

variable "qualification_manifest_seed" {
  description = "Explicit, reviewed G0 output. G0 has local authoritative state; this must not be discovered through terraform_remote_state."
  type = object({
    schema_version            = number
    environment               = string
    environment_is_production = bool
    account_id                = string
    region                    = string
    namespace                 = string
    cell_id                   = string
    required_tags             = map(string)
    terraform_state = object({
      bucket         = string
      kms_alias      = string
      key_prefix     = string
      use_lockfile   = bool
      state_role_arn = string
    })
  })
}

variable "formation_mode" {
  description = "True only for the independently reviewed one-time formation plan; false requires the H2 reconcile role."
  type        = bool
  default     = false
}

variable "formation_principal_arn" {
  description = "Exact G0-authorized bootstrap principal permitted only for the one-time formation plan."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::${var.expected_account_id}:(user|role)/[A-Za-z0-9+=,.@_/-]+$", var.formation_principal_arn))
    error_message = "formation_principal_arn must be one exact IAM user or role in the approved account."
  }
}
