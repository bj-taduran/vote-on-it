##############################################################################
# main.tf — Bootstrap Module for Terraform Remote State
#
# Security Features Included:
#   - S3 Versioning (Protects against accidental state corruption/deletion)
#   - S3 Default Encryption (AES-256)
#   - S3 Public Access Block (Prevents accidental data exposure)
#   - DynamoDB State Locking (Prevents concurrent modification corruption)
##############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  # Hardcoded to Frankfurt to match your intended deployment region
  region = "eu-central-1"
  profile = "vote-on-it-deployer-ic"

  default_tags {
    tags = {
      Project     = "vote-on-it"
      Component   = "Terraform-Backend"
      ManagedBy   = "Terraform"
      Security    = "Critical"
    }
  }
}

# ---------------------------------------------------------------------------
# S3 Bucket for State Storage
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "terraform_state" {
  # MUST BE GLOBALLY UNIQUE.
  bucket = "vote-on-it-tfstate-bjt"

  lifecycle {
    prevent_destroy = true # Prevents accidental deletion of your state
  }
}

# Enforce Versioning
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enforce Encryption at Rest (SSE-S3)
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access entirely
resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# DynamoDB Table for State Locking
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "terraform_state_lock" {
  name         = "terraform-state-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

# ---------------------------------------------------------------------------
# Outputs to copy into your main project
# ---------------------------------------------------------------------------
output "state_bucket_name" {
  value = aws_s3_bucket.terraform_state.bucket
}

output "dynamodb_lock_table" {
  value = aws_dynamodb_table.terraform_state_lock.name
}
