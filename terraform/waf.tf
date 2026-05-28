##############################################################################
# waf.tf — WAFv2 WebACL for CloudFront (CKV_AWS_68, CKV2_AWS_47).
#
# Security notes:
#   - CloudFront WAF WebACLs MUST be created in us-east-1, regardless of the
#     application's primary region. A provider alias handles this.
#   - AWS Managed Rule Groups provide OWASP Top 10 and Log4j protection with
#     zero maintenance overhead. Custom rules can be added alongside them.
#   - SOC2: WAF logs ship to the same CloudWatch log group as the API Gateway.
#
# GDPR note:
#   - WAF rules are stateless filters — no personal data is stored in us-east-1.
#     CloudFront edge processing is the only US-touched path; the origin and
#     all persistence remain in eu-* per PriceClass_100 and DynamoDB placement.
##############################################################################

resource "aws_wafv2_web_acl" "cloudfront" {
  provider = aws.us_east_1

  name        = "${var.project_name}-${var.environment}-cloudfront-waf"
  description = "WAF for vote-on-it CloudFront distribution. Blocks OWASP Top 10 and known bad inputs."
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # AWS Managed: Core rule set — OWASP Top 10, common web exploits.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed: Known bad inputs — Log4j, SSRF, Spring4Shell (CKV2_AWS_47).
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed: IP reputation — blocks IPs associated with botnets and scanners.
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-${var.environment}-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name       = "${var.project_name}-${var.environment}-cloudfront-waf"
    Compliance = "SOC2"
  }
}

# ---------------------------------------------------------------------------
# WAF Logging (CKV2_AWS_31)
# Log group name MUST start with "aws-waf-logs-" — this is an AWS requirement.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "waf" {
  #checkov:skip=CKV_AWS_158:WAF log group is in us-east-1; the project CMK is eu-* regional. A cross-region CMK for WAF logs would require a separate key lifecycle with disproportionate operational overhead.
  provider          = aws.us_east_1
  name              = "aws-waf-logs-${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name       = "${var.project_name}-${var.environment}-waf-logs"
    DataClass  = "Audit"
    Compliance = "SOC2"
  }
}

# Resource policy grants WAFv2 permission to write to the log group.
# delivery.logs.amazonaws.com is the WAFv2 log-delivery service principal.
resource "aws_cloudwatch_log_resource_policy" "waf" {
  provider    = aws.us_east_1
  policy_name = "${var.project_name}-${var.environment}-waf-logs-policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.waf.arn}:*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "cloudfront" {
  provider                = aws.us_east_1
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.cloudfront.arn

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
