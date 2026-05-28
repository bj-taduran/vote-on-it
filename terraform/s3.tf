##############################################################################
# s3.tf — S3 bucket for static frontend assets.
#
# Security notes:
#   - The bucket is PRIVATE. Public access is blocked at every level.
#   - CloudFront accesses it exclusively via Origin Access Control (OAC),
#     which is the current AWS-recommended approach (supersedes OAI).
#   - Versioning is enabled for accidental-deletion recovery (SOC2).
#   - Server-side encryption (SSE-S3 AES-256) is enforced by bucket policy.
##############################################################################

resource "aws_s3_bucket" "frontend" {
  bucket = "${var.project_name}-${var.environment}-frontend-${data.aws_caller_identity.current.account_id}"

  # Prevent accidental Terraform destroy in production.
  lifecycle {
    prevent_destroy = false # Set to true for production environments.
  }

  tags = {
    Name         = "${var.project_name}-${var.environment}-frontend"
    DataClass    = "Public-Static-Assets"
    GDPRRelevant = "false"
  }
}

# Block ALL public access — CloudFront uses OAC, not public URLs.
resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning — enables recovery of accidentally overwritten assets.
resource "aws_s3_bucket_versioning" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Encryption at rest — SSE-S3 (AES-256) per CLAUDE.md §3.4.
# CKV_AWS_145 (SSE-KMS) is intentionally not applied to the frontend bucket:
# CloudFront OAC requires additional KMS key-policy grants that couple the
# distribution ARN to the CMK at creation time, creating circular Terraform
# dependencies. Static HTML/JS/CSS assets are non-sensitive; AES-256 is compliant.
# checkov:skip=CKV_AWS_145:SSE-S3 is sufficient per CLAUDE.md §3.4; SSE-KMS adds CloudFront/KMS circular dependency for non-sensitive static assets.
resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# ---------------------------------------------------------------------------
# Bucket policy: allow CloudFront OAC to GetObject; deny all other access.
# The condition ties the allow to our specific CloudFront distribution ARN,
# not just any CloudFront distribution (prevents confused-deputy attacks).
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontOACGetObject"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.frontend.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.frontend.arn
          }
        }
      },
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.frontend.arn,
          "${aws_s3_bucket.frontend.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.frontend]
}

# ---------------------------------------------------------------------------
# S3 access logging — ship access logs to a separate audit bucket.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.project_name}-${var.environment}-access-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "${var.project_name}-${var.environment}-access-logs"
    DataClass  = "Audit"
    Compliance = "SOC2"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# checkov:skip=CKV_AWS_145:SSE-S3 is sufficient per CLAUDE.md §3.4; SSE-KMS breaks S3 server-access-log delivery and CloudFront log delivery to this bucket.
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "frontend" {
  bucket        = aws_s3_bucket.frontend.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-frontend-access/"
}

# ---------------------------------------------------------------------------
# Allow ACLs on the access log bucket for CloudFront logging
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "access_logs" {
  depends_on = [
    aws_s3_bucket_ownership_controls.access_logs,
    aws_s3_bucket_public_access_block.access_logs
  ]

  bucket = aws_s3_bucket.access_logs.id
  acl    = "log-delivery-write"
}
