terraform {
  required_version = ">= 1.10, < 2.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.2"
    }

    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.26"
    }
  }
}
