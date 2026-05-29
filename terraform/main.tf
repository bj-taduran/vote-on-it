##############################################################################
# main.tf — Provider configuration and remote state backend
#
# Compliance notes:
#   - SOC2: All resources are tagged for asset inventory and auditability.
#   - GDPR:  The AWS region is explicitly constrained to eu-central-1 to satisfy
#             EU data residency requirements. Change if your residency differs.
##############################################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # ---------------------------------------------------------------------------
  # Remote state: store tfstate in S3 with DynamoDB locking.
  # Uncomment and populate before running `terraform init` in a real deployment.
  # ---------------------------------------------------------------------------
  # backend "s3" {
  #   bucket         = "vote-on-it-tfstate-bjt"
  #   key            = "vote-on-it/terraform.tfstate"
  #   region         = "eu-central-1"
  #   dynamodb_table = "terraform-state-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Compliance  = "SOC2-GDPR"
    }
  }
}

# WAFv2 WebACLs for CloudFront MUST be created in us-east-1 regardless of the
# application's primary region. This alias is used exclusively for WAF resources.
# No EU personal data transits or is stored in this region.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Compliance  = "SOC2-GDPR"
    }
  }
}
