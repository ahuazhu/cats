terraform {
  required_version = ">= 1.10, < 2.0"

  backend "s3" {}

  required_providers {
    stripe = {
      source  = "stripe/stripe"
      version = "~> 0.2.2"
    }
  }
}

provider "stripe" {}
