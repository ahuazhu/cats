variable "name_prefix" {
  type        = string
  description = "Resource name prefix."
  default     = "cats"
}

variable "environment" {
  type        = string
  description = "Deployment environment name."
}

variable "aws_region" {
  type        = string
  description = "Region hosting the VPC; used for the S3 gateway endpoint service name."
}

variable "vpc_cidr" {
  type        = string
  description = "IPv4 CIDR for the VPC."
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrsubnet(var.vpc_cidr, 4, 15))
    error_message = "vpc_cidr must be at least a /20 so the module can carve eight public and eight private subnets."
  }
}

variable "availability_zone_count" {
  type        = number
  description = "Number of availability zones. An ALB needs at least two."
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2 && var.availability_zone_count <= 8
    error_message = "availability_zone_count must be between 2 and 8."
  }
}

variable "one_nat_gateway_per_az" {
  type        = bool
  description = "Provision a NAT gateway per zone instead of one shared gateway. Costs roughly $32/month per extra gateway."
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Additional tags."
  default     = {}
}
