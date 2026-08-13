variable "name_prefix" {
  type    = string
  default = "cats"
}

variable "environment" {
  type = string
}

variable "expected_account_id" {
  description = "Exact AWS account containing the worker and its Route v2 artifact secret."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be an explicit 12-digit AWS account ID."
  }
}

variable "expected_aws_partition" {
  description = "Exact AWS partition containing the worker and its Route v2 artifact secret."
  type        = string
  nullable    = false

  validation {
    condition = contains([
      "aws",
      "aws-cn",
      "aws-iso",
      "aws-iso-b",
      "aws-iso-e",
      "aws-iso-f",
      "aws-us-gov",
    ], var.expected_aws_partition)
    error_message = "expected_aws_partition must name one supported AWS partition."
  }
}

variable "aws_region" {
  description = "Exact AWS region containing the worker and its Route v2 artifact secret."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be an explicit AWS region name."
  }
}

variable "artifact_bucket_name" {
  description = "Globally unique bucket for immutable worker deployment bundles and SSM output."
  type        = string
}

variable "chunkstore_prefix" {
  description = "Exact canonical object-key prefix shared with cats-controld and usage IAM."
  type        = string

  validation {
    condition = (
      var.chunkstore_prefix != "" &&
      !startswith(var.chunkstore_prefix, "/") &&
      !endswith(var.chunkstore_prefix, "/") &&
      !strcontains(var.chunkstore_prefix, "..") &&
      !strcontains(var.chunkstore_prefix, "//") &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$", var.chunkstore_prefix))
    )
    error_message = "chunkstore_prefix must be one non-empty relative canonical prefix."
  }
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

variable "instances" {
  description = <<-EOT
    Existing Cats bare-metal EC2 instances keyed by a stable worker name such
    as "metal-1". The key names the worker's deployment association and is
    what deploy_instances selects during a rolling release.
  EOT
  type        = map(string)

  validation {
    condition     = length(var.instances) > 0
    error_message = "instances must contain at least one worker."
  }

  validation {
    condition     = alltrue([for name, id in var.instances : can(regex("^i-[0-9a-f]+$", id))])
    error_message = "instances values must be EC2 instance IDs."
  }

  validation {
    condition     = alltrue([for name, id in var.instances : can(regex("^[a-z0-9][a-z0-9-]{0,62}$", name))])
    error_message = "instances keys must be short lowercase names usable in an SSM association name."
  }
}

variable "deploy_instances" {
  description = <<-EOT
    Worker names whose deployment association exists this apply; null means
    every instance. Deploying re-runs the association, and require-idle-worker
    only lets that run on a drained host, so a release across a serving fleet
    goes one worker at a time: drain one, list only it here, apply, undrain,
    repeat. A worker left out keeps running its installed version -- its
    association is removed, not its software.

    Never subset an apply that changes worker_runtime_secret_data: this
    association is the only path that removes a retired secret or compatibility
    value from an existing host. Roll that cleanup through every drained worker.
  EOT
  type        = set(string)
  default     = null
  nullable    = true

  validation {
    condition = (
      var.deploy_instances == null
      ? true
      : length(setsubtract(var.deploy_instances, toset(keys(var.instances)))) == 0
    )
    error_message = "deploy_instances must be a subset of the keys of instances."
  }
}

variable "instance_role_name" {
  description = "Existing IAM role shared by every bare-metal worker's instance profile."
  type        = string
}

variable "worker_runtime_secret_data" {
  description = "Optional compatibility values overlaid onto worker.env. Signed workers receive no shared Control bearer."
  type        = map(string)
  sensitive   = true

  # CATS_POSTGRES_URL is accepted but no longer required, and nothing reads it
  # once the worker passes url-file: the DSN is rendered from the managed
  # secret at every start. Drop it from this map when the fleet has cut over.
  validation {
    condition = (
      length(setsubtract(
        toset(keys(var.worker_runtime_secret_data)),
        toset(["CATS_POSTGRES_URL"])
      )) == 0 &&
      alltrue([
        for value in values(var.worker_runtime_secret_data) :
        length(trimspace(value)) > 0 &&
        !strcontains(value, "\n") && !strcontains(value, "\r")
      ])
    )
    error_message = "worker_runtime_secret_data may contain only a non-empty single-line legacy CATS_POSTGRES_URL; signed workers must not receive CATS_AUTH_TOKEN."
  }
}

variable "route_v2_node_artifact_secret_arn" {
  description = "ARN of the pre-created Secrets Manager value containing the exact four base64-encoded Node Route v2 artifacts. Terraform receives only the ARN."
  type        = string

  validation {
    condition = (
      startswith(
        var.route_v2_node_artifact_secret_arn,
        "arn:${var.expected_aws_partition}:secretsmanager:${var.aws_region}:${var.expected_account_id}:secret:${var.name_prefix}-${var.environment}-route-v2-node-r1-",
      ) &&
      length(var.route_v2_node_artifact_secret_arn) == length("arn:${var.expected_aws_partition}:secretsmanager:${var.aws_region}:${var.expected_account_id}:secret:${var.name_prefix}-${var.environment}-route-v2-node-r1-") + 6 &&
      can(regex("[A-Za-z0-9]{6}$", var.route_v2_node_artifact_secret_arn))
    )
    error_message = "route_v2_node_artifact_secret_arn must identify the exact <name-prefix>-<environment>-route-v2-node-r1 secret in the expected partition, account, and region; rotation is outside the initial G2 contract."
  }
}

variable "route_v2_node_artifact_secret_version_id" {
  description = "Exact immutable Secrets Manager version ID selected for the revision-1 Node Route v2 artifact secret."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9-]{32,64}$", var.route_v2_node_artifact_secret_version_id))
    error_message = "route_v2_node_artifact_secret_version_id must be a 32-64 character Secrets Manager version ID."
  }
}

variable "database_master_user_secret_arn" {
  description = <<-EOT
    ARN of the RDS managed master user secret, the one authority for the
    database password. Set it and the worker renders its DSN from it at every
    start and on a timer, so a rotation costs nothing; leave it null and the
    worker keeps using whatever CATS_POSTGRES_URL is in worker.env, which is
    the arrangement that turned a rotation into an outage.
  EOT
  type        = string
  default     = null

  validation {
    condition = (
      var.database_master_user_secret_arn == null ||
      can(regex("^arn:[^:]+:secretsmanager:", var.database_master_user_secret_arn))
    )
    error_message = "database_master_user_secret_arn must be a Secrets Manager ARN."
  }
}

variable "worker_managed_environment" {
  description = <<-EOT
    Non-secret worker.env entries Terraform owns outright and rewrites on every
    deployment, unlike worker_base_environment which only seeds a host that has
    no file yet. Use it for values that must reach an existing host --
    CATS_POSTGRES_HOST, CATS_POSTGRES_PORT, CATS_POSTGRES_DATABASE,
    CATS_POSTGRES_SSLMODE, CATS_POSTGRES_SESSION_SETUP.
    CATS_POSTGRES_SECRET_ARN is added automatically from
    database_master_user_secret_arn.
  EOT
  type        = map(string)
  default     = {}

  # CATS_POSTGRES_SECRET_ARN is blocked here even though it is not a secret.
  # Setting it directly delivers the ARN to worker.env without emitting the IAM
  # statement that grants GetSecretValue on it, because that statement is keyed
  # on database_master_user_secret_arn. The renderer then fails with
  # AccessDeniedException in ExecStartPre and cats-worker does not start -- a
  # host wedged by a Terraform apply that validated cleanly. The two must move
  # together, so there is one way to set them.
  validation {
    condition = length(setintersection(
      toset(keys(var.worker_managed_environment)),
      toset([
        "CATS_AUTH_TOKEN",
        "CATS_CHUNKSTORE_PREFIX",
        "CATS_POSTGRES_URL",
        "CATS_POSTGRES_SECRET_ARN",
        "CATS_METERING_CGROUP_ROOT",
        "CATS_NODE_ID",
        "CATS_NODE_ADVERTISE_URL",
        "CATS_ROUTE_V2_MACHINE_LISTEN",
      ]),
    )) == 0
    error_message = "CATS_AUTH_TOKEN is forbidden on signed workers; CATS_CHUNKSTORE_PREFIX comes only from chunkstore_prefix; CATS_POSTGRES_SECRET_ARN goes through database_master_user_secret_arn so the matching IAM statement is emitted with it; CATS_METERING_CGROUP_ROOT is discovered on the host; node identity is per worker; the Route v2 listener is fixed by the production unit."
  }

  validation {
    condition = alltrue([
      for value in values(var.worker_managed_environment) :
      length(trimspace(value)) > 0 && !strcontains(value, "\n") && !strcontains(value, "\r")
    ])
    error_message = "worker_managed_environment values must be non-empty and single-line."
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

variable "worker_base_environment" {
  description = <<-EOT
    Non-secret, fleet-shared worker.env entries used only when the host has no
    worker.env yet -- control plane and gateway URLs, region, ChunkStore
    bucket, guest network CIDR. An existing file is never rewritten, so
    operator edits survive. Secrets belong in worker_runtime_secret_data;
    CATS_METERING_CGROUP_ROOT is discovered on the host; Node identity is a
    provisioner-owned artifact and must not be set here.
  EOT
  type        = map(string)
  default     = {}

  validation {
    condition     = !contains(keys(var.worker_base_environment), "CATS_METERING_CGROUP_ROOT")
    error_message = "CATS_METERING_CGROUP_ROOT is discovered from the host's cgroup2 mount and systemd slice; do not pin it."
  }

  validation {
    condition = length(setintersection(
      toset(keys(var.worker_base_environment)),
      toset(["CATS_AUTH_TOKEN", "CATS_CHUNKSTORE_PREFIX", "CATS_POSTGRES_URL"]),
    )) == 0
    error_message = "CATS_AUTH_TOKEN is forbidden on signed workers; CATS_CHUNKSTORE_PREFIX comes only from chunkstore_prefix; the retired CATS_POSTGRES_URL compatibility value may only use worker_runtime_secret_data."
  }

  # Everything in this map reaches every fresh host identically, and a second
  # host seeded with the first one's identity registers as its duplicate.
  validation {
    condition = length(setintersection(
      toset(keys(var.worker_base_environment)),
      toset(["CATS_NODE_ID", "CATS_NODE_ADVERTISE_URL", "CATS_ROUTE_V2_MACHINE_LISTEN"]),
    )) == 0
    error_message = "Node identity is provisioner-owned artifact data and the Route v2 listener is fixed by the production unit; environment and IMDS overrides are forbidden."
  }
}
