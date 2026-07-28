variable "name_prefix" {
  type        = string
  description = "Resource name prefix."
  default     = "cats"
}

variable "github_repository" {
  type        = string
  description = "owner/name of the repository allowed to assume the role."

  validation {
    condition     = can(regex("^[^/]+/[^/]+$", var.github_repository))
    error_message = "github_repository must be in owner/name form."
  }
}

variable "subject_repository" {
  type        = string
  description = <<-EOT
    Repository exactly as it appears in the OIDC `sub` claim, when that differs
    from `github_repository`. GitHub mints `owner@<owner_id>/name@<repo_id>` for
    repositories using immutable subject claims. Null uses `github_repository`.
  EOT
  default     = null
}

variable "default_branch" {
  type        = string
  description = "Branch allowed to release when allowed_subjects is not set."
  default     = "main"
}

variable "allowed_subjects" {
  type        = list(string)
  description = <<-EOT
    Explicit `token.actions.githubusercontent.com:sub` patterns. Overrides the
    default branch/tag pair. Never widen this to `repo:owner/*` — the subject
    condition is the only thing preventing another repository from assuming the
    role.
  EOT
  default     = []
}

variable "create_oidc_provider" {
  type        = bool
  description = "Create the GitHub OIDC provider. Set false if the account already has one; an account may only have one per URL."
  default     = true
}

variable "existing_oidc_provider_arn" {
  type        = string
  description = "Provider ARN to reuse when create_oidc_provider is false."
  default     = null
}

variable "oidc_thumbprints" {
  type        = list(string)
  description = "Root CA thumbprints for the GitHub OIDC endpoint. AWS verifies this provider itself, so these are accepted but not relied upon."
  default = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

variable "ecr_repository_arns" {
  type        = list(string)
  description = "ECR repositories the release role may push to."
}

variable "tags" {
  type        = map(string)
  description = "Additional tags."
  default     = {}
}
