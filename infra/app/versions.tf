terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  # Filled in at `terraform init` (see README): bucket from infra/bootstrap, key, region,
  # use_lockfile=true (S3-native state locking, no DynamoDB lock table needed).
  backend "s3" {}
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = var.name, ManagedBy = "terraform", Stack = "app" }
  }
}

data "aws_caller_identity" "me" {}

locals {
  account     = data.aws_caller_identity.me.account_id
  api_name    = "${var.name}-api"
  worker_name = "${var.name}-worker"
}
