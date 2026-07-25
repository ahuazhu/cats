variable "name_prefix" {
  type    = string
  default = "cats"
}

variable "environment" {
  type = string
}

variable "artifact_bucket_name" {
  description = "Globally unique bucket for immutable worker deployment bundles and SSM output."
  type        = string
}

variable "worker_bundle_path" {
  description = "Absolute local path to the reviewed linux/amd64 worker tar.zst bundle."
  type        = string

  validation {
    condition     = startswith(var.worker_bundle_path, "/")
    error_message = "worker_bundle_path must be absolute."
  }
}

variable "worker_bundle_sha256" {
  description = "Lowercase SHA-256 digest of worker_bundle_path."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.worker_bundle_sha256))
    error_message = "worker_bundle_sha256 must contain 64 lowercase hexadecimal characters."
  }
}

variable "instance_id" {
  description = "Existing Cats bare-metal EC2 instance managed by the SSM association."
  type        = string

  validation {
    condition     = can(regex("^i-[0-9a-f]+$", var.instance_id))
    error_message = "instance_id must be an EC2 instance ID."
  }
}

variable "instance_role_name" {
  description = "Existing IAM role attached to the bare-metal instance profile."
  type        = string
}

variable "worker_runtime_secret_data" {
  description = "Runtime credentials overlaid onto the existing worker environment file through Secrets Manager."
  type        = map(string)
  sensitive   = true

  validation {
    condition = (
      length(setsubtract(
        toset(keys(var.worker_runtime_secret_data)),
        toset(["CATS_AUTH_TOKEN", "CATS_POSTGRES_URL"])
      )) == 0 &&
      alltrue([
        for key in ["CATS_AUTH_TOKEN", "CATS_POSTGRES_URL"] :
        try(length(trimspace(var.worker_runtime_secret_data[key])) > 0, false)
      ]) &&
      alltrue([
        for value in values(var.worker_runtime_secret_data) :
        !strcontains(value, "\n") && !strcontains(value, "\r")
      ])
    )
    error_message = "worker_runtime_secret_data must contain only non-empty, single-line CATS_AUTH_TOKEN and CATS_POSTGRES_URL values."
  }
}

variable "install_root" {
  description = "Existing Cats installation root on the worker."
  type        = string
  default     = "/opt/cats"

  validation {
    condition     = startswith(var.install_root, "/") && var.install_root != "/"
    error_message = "install_root must be an absolute non-root path."
  }
}

variable "worker_environment_file" {
  description = "Existing root-only worker environment file."
  type        = string
  default     = "/etc/cats/worker.env"

  validation {
    condition     = startswith(var.worker_environment_file, "/")
    error_message = "worker_environment_file must be absolute."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
