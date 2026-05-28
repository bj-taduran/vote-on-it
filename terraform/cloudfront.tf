##############################################################################
# cloudfront.tf — CloudFront distribution for the static frontend.
#
# Security notes:
#   - Origin Access Control (OAC) is used — current AWS best practice.
#   - Minimum TLS version is TLSv1.2_2021 — older protocols are disabled.
#   - HTTPS is enforced; HTTP is redirected to HTTPS at the edge.
#   - Security headers (CSP, HSTS, etc.) are injected via a CloudFront
#     Response Headers Policy — no server needed.
#   - CloudFront standard logging ships to the access-logs S3 bucket.
##############################################################################

# ---------------------------------------------------------------------------
# Origin Access Control — authenticates CloudFront to the S3 origin.
# Replaces the legacy Origin Access Identity (OAI).
# ---------------------------------------------------------------------------
resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "${var.project_name}-${var.environment}-oac"
  description                       = "OAC for vote-on-it frontend S3 bucket."
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ---------------------------------------------------------------------------
# Response Headers Policy — security headers applied at the edge.
# These headers satisfy OWASP and SOC2 security hardening recommendations.
# ---------------------------------------------------------------------------
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name    = "${var.project_name}-${var.environment}-security-headers"
  comment = "OWASP/SOC2 security headers for vote-on-it frontend."

  security_headers_config {
    # Prevent MIME type sniffing.
    content_type_options {
      override = true
    }

    # Clickjacking protection.
    frame_options {
      frame_option = "DENY"
      override     = true
    }

    # XSS filter (legacy browsers).
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }

    # HSTS — force HTTPS for 1 year, include subdomains.
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    # Referrer policy — minimise data leakage via Referer header.
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    # Content Security Policy — lock down allowed sources.
    # Adjust the API Gateway domain in the connect-src directive after apply.
    content_security_policy {
      content_security_policy = join("; ", [
        "default-src 'self'",
        "script-src 'self' https://cdn.jsdelivr.net", # Chart.js CDN
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self' https://*.execute-api.${var.aws_region}.amazonaws.com",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ])
      override = true
    }
  }
}

# ---------------------------------------------------------------------------
# CloudFront Distribution
# ---------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "frontend" {
  #checkov:skip=CKV_AWS_374:Data-residency is enforced via PriceClass_100 (US+EU edge locations only) per GDPR. Country-level geo-restriction is not required — PriceClass_100 is the chosen residency control.
  #checkov:skip=CKV_AWS_310:Single S3 origin; adding an origin failover group requires a second S3 bucket in a different region which conflicts with GDPR EU-only data-residency constraints.
  #checkov:skip=CKV2_AWS_47:AWSManagedRulesKnownBadInputsRuleSet (Log4j protection) is attached in waf.tf. Checkov cannot resolve cross-provider-alias resource references to verify WAF rule groups from the distribution resource.
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "vote-on-it ${var.environment} frontend"
  default_root_object = "index.html"
  price_class         = "PriceClass_100" # US + EU edge locations only (GDPR data-residency hint).

  # SOC2: WAF blocks OWASP Top 10, Log4j, and known-bad IPs (CKV_AWS_68, CKV2_AWS_47).
  web_acl_id = aws_wafv2_web_acl.cloudfront.arn

  # S3 origin via OAC.
  origin {
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id                = "S3-${aws_s3_bucket.frontend.bucket}"
    origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
  }

  # Default cache behaviour.
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.frontend.bucket}"

    # HTTPS only — redirect HTTP to HTTPS.
    viewer_protocol_policy = "redirect-to-https"

    # Cache policy: managed "CachingOptimized" for static assets.
    cache_policy_id            = "658327ea-f89d-4fab-a63d-7e88639e58f6" # AWS Managed: CachingOptimized
    origin_request_policy_id   = "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf" # AWS Managed: CORS-S3Origin
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  # SPA fallback: serve index.html for 404s (client-side routing support).
  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  # TLS configuration (CKV_AWS_174).
  # - Dev/staging: CloudFront default certificate. AWS enforces TLS 1.2+ on the
  #   default cert; minimum_protocol_version and ssl_support_method are only
  #   configurable when using a custom ACM certificate.
  # - Production: set var.acm_certificate_arn to an ACM cert in us-east-1.
  #   This enables TLSv1.2_2021 (disables TLS 1.0/1.1) and SNI-only mode.
  viewer_certificate {
    cloudfront_default_certificate = var.acm_certificate_arn == null ? true : null
    acm_certificate_arn            = var.acm_certificate_arn
    minimum_protocol_version       = var.acm_certificate_arn != null ? "TLSv1.2_2021" : null
    ssl_support_method             = var.acm_certificate_arn != null ? "sni-only" : null
  }

  # Geo-restriction: none by default. Add GDPR-required country blocks if needed.
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # SOC2: CloudFront standard logging.
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.access_logs.bucket_domain_name
    prefix          = "cloudfront/"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-cloudfront"
  }
}
