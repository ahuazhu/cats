variable "aws_region" {
  description = "Region for the Terraform state bucket."
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Globally unique Terraform state bucket name."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
