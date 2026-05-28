##############################################################################
# api_gateway.tf — HTTP API (API Gateway v2) with CORS and throttling.
#
# Security notes:
#   - API Gateway v2 (HTTP API) is used over REST API for lower latency and cost.
#   - CORS is locked to the CloudFront distribution domain — no wildcard origins.
#   - Throttling limits are set to mitigate abuse (not a substitute for WAF in prod).
#   - In production, attach an AWS WAF WebACL to this API for rate limiting and
#     geo-blocking beyond what throttling alone provides.
##############################################################################

resource "aws_apigatewayv2_api" "vote" {
  name          = "${var.project_name}-${var.environment}-api"
  protocol_type = "HTTP"
  description   = "Vote-on-it HTTP API. Exposes POST /vote and GET /results."

  # CORS: locked to the CloudFront origin. Wildcards (*) are not permitted
  # per our security policy.
  cors_configuration {
    allow_origins = ["https://${aws_cloudfront_distribution.frontend.domain_name}"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "X-Request-ID"]
    max_age       = 300 # 5 minutes — browser pre-flight cache.
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-api"
  }
}

# ---------------------------------------------------------------------------
# Lambda integration — proxy all requests to the Go Lambda.
# ---------------------------------------------------------------------------
resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.vote.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.vote.invoke_arn
  integration_method     = "POST" # API GW always POSTs to Lambda internally.
  payload_format_version = "2.0"  # Lambda payload format v2 — cleaner event struct.
}

# ---------------------------------------------------------------------------
# Routes — only the two required endpoints are exposed.
# ---------------------------------------------------------------------------
resource "aws_apigatewayv2_route" "post_vote" {
  #checkov:skip=CKV_AWS_309:This is a public polling endpoint — authorization is intentionally absent. Input validation and dedup are enforced inside the Lambda handler.
  api_id             = aws_apigatewayv2_api.vote.id
  route_key          = "POST /vote"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "get_results" {
  #checkov:skip=CKV_AWS_309:GET /results is intentionally public — live vote percentages are not sensitive data.
  api_id             = aws_apigatewayv2_api.vote.id
  route_key          = "GET /results"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "NONE"
}

# ---------------------------------------------------------------------------
# Stage — auto-deploy on change; throttling prevents vote-flood abuse.
# ---------------------------------------------------------------------------
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.vote.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    # Throttling: burst of 50 concurrent requests, sustained at 20 rps.
    # Tune upward for production traffic; add WAF for DDoS protection.
    throttling_burst_limit = 50
    throttling_rate_limit  = 20

    # SOC2: detailed metrics and logging enabled.
    detailed_metrics_enabled = true
    logging_level            = "INFO"
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn

    # SOC2 compliant logging, intentionally omitting $context.identity.sourceIp for GDPR.
    format = jsonencode({
      requestId               = "$context.requestId"
      requestTime             = "$context.requestTime"
      protocol                = "$context.protocol"
      httpMethod              = "$context.httpMethod"
      resourcePath            = "$context.resourcePath"
      routeKey                = "$context.routeKey"
      status                  = "$context.status"
      responseLength          = "$context.responseLength"
      integrationErrorMessage = "$context.integrationErrorMessage"
    })
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-api-stage"
  }
}

# ---------------------------------------------------------------------------
# API Gateway access log group — separate from Lambda logs.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  # SOC2: CMK encrypts API access logs at rest (CKV_AWS_158).
  kms_key_id = aws_kms_key.main.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-api-logs"
    DataClass  = "Audit"
    Compliance = "SOC2"
  }
}
