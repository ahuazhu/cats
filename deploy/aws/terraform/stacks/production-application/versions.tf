terraform {
  required_version = ">= 1.10, < 2.0"

  backend "s3" {}

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

provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kubeconfig_context
}

provider "aws" {
  region = var.aws_region
}
