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
