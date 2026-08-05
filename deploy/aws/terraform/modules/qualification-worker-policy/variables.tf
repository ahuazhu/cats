variable "partition" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "ami_id" { type = string }
variable "snapshot_arns" {
  description = "Exact EBS snapshot ARNs referenced by the fixed AMI. EC2 snapshot ARNs deliberately have an empty account segment."
  type        = set(string)

  validation {
    condition = length(var.snapshot_arns) == 1 && alltrue([
      for arn in var.snapshot_arns : can(regex(
        "^arn:${var.partition}:ec2:${var.region}::snapshot/snap-[0-9a-f]+$",
        arn,
      ))
    ])
    error_message = "snapshot_arns must contain exactly the fixed AMI root snapshot ARN in partition/region, with the EC2-defined empty account segment."
  }
}
variable "subnet_id" { type = string }
variable "security_group_id" { type = string }
variable "instance_type" { type = string }
variable "instance_profile_arn" { type = string }
variable "worker_role_arn" { type = string }
variable "artifact_bucket_arn" { type = string }
