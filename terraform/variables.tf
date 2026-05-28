##############################################################################
# variables.tf — All configurable inputs for the vote-on-it stack.
#
# Values are provided via a terraform.tfvars file (git-ignored) or via
# environment variables (TF_VAR_*). No defaults contain sensitive data.
##############################################################################

variable "aws_region" {
  description = "AWS region. Must be an EU region to satisfy GDPR data-residency requirements."
  type        = string
  default     = "eu-central-1"

  validation {
    condition     = can(regex("^eu-", var.aws_region))
    error_message = "GDPR compliance requires an EU AWS region (e.g. eu-west-1, eu-central-1)."
  }
}

variable "project_name" {
  description = "Short name used as a prefix for all resource names."
  type        = string
  default     = "vote-on-it"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,28}[a-z0-9]$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric with hyphens, 4-30 chars."
  }
}

variable "environment" {
  description = "Deployment environment. Controls naming and certain compliance controls."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "poll_question" {
  description = "The question displayed to voters. Stored as an SSM parameter, not in code."
  type        = string
  default     = "What is the best programming language?"
}

variable "poll_options" {
  description = "Exactly 4 answer options for the poll."
  type        = list(string)
  default     = ["Go", "Rust", "Python", "TypeScript"]

  validation {
    condition     = length(var.poll_options) == 4
    error_message = "Exactly 4 poll options are required."
  }
}

variable "lambda_memory_mb" {
  description = "Memory allocated to the Lambda function in MB."
  type        = number
  default     = 128

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 10240
    error_message = "Lambda memory must be between 128 MB and 10240 MB."
  }
}

variable "lambda_timeout_seconds" {
  description = "Maximum Lambda execution time in seconds."
  type        = number
  default     = 10
}

variable "voter_dedup_ttl_hours" {
  description = "How long (in hours) a voter hash is retained in VoterLog to prevent re-voting."
  type        = number
  default     = 24
}

variable "log_retention_days" {
  description = "CloudWatch log group retention in days. 365 days satisfies typical SOC2 log retention."
  type        = number
  default     = 365
}

variable "acm_certificate_arn" {
  description = "ARN of an ACM certificate in us-east-1 for CloudFront HTTPS on a custom domain. Leave null for dev/staging (CloudFront default certificate is used — TLS 1.2+ enforced by AWS). Required for production to enable TLSv1.2_2021 minimum_protocol_version."
  type        = string
  default     = null
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrent executions for the Lambda function. Limits blast radius from traffic spikes; should be set above the API Gateway throttling burst limit (default 50). Use -1 for unreserved (draws from account pool)."
  type        = number
  default     = 100
}
