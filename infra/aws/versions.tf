# SecureFlow AI — the public environment on AWS (docs/operations.md §6, docs/architecture.md §14 D33–D36).
#
# One Terraform root module, applied by the operator from their own machine with their own credentials
# (`AWS_PROFILE=terraform terraform apply`, or aws_profile in terraform.tfvars). The state stays on that machine
# (*.tfstate is ignored by git); nothing in CI holds AWS credentials. Secrets never go through Terraform:
# put-secrets.sh writes them to the parameter store directly, so they are not in the state either.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
    }
  }
}
