terraform {
  required_version = ">= 1.10, < 2.0"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.26"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Cats"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
