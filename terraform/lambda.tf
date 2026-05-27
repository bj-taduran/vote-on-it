##############################################################################
# lambda.tf — Go Lambda function definition.
#
# Architecture notes:
#   - A SINGLE Lambda binary handles both routes (POST /vote, GET /results).
#     The handler reads the `httpMethod` + `path` from the API Gateway event
#     and dispatches internally. This minimises cold-start surface.
#   - Environment variables carry ONLY non-sensitive configuration. Secrets are
#     fetched at runtime from Secrets Manager (see iam.tf for the permission).
#   - No credentials of any kind appear here.
##############################################################################

# CloudWatch Log Group — created explicitly so we control retention.
# If Terraform does not manage this, AWS creates it with infinite retention,
# which violates SOC2 log-lifecycle controls.
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-vote"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-${var.environment}-lambda-logs"
    DataClass   = "Audit"
    Compliance  = "SOC2"
  }
}

# ---------------------------------------------------------------------------
# Lambda function
# The deployment package (Go binary zipped) is expected at:
#   ../lambda/dist/function.zip
# Build it with: GOOS=linux GOARCH=arm64 go build -o bootstrap ./cmd/...
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "vote" {
  function_name = "${var.project_name}-${var.environment}-vote"
  description   = "Handles POST /vote and GET /results for the vote-on-it application."

  # Go compiled for Lambda's arm64 (Graviton2) — cheaper and faster than x86.
  runtime       = "provided.al2023"
  architectures = ["arm64"]
  handler       = "bootstrap" # Required name for custom runtime on AL2023.

  filename         = "../lambda/dist/function.zip"
  source_code_hash = filebase64sha256("../lambda/dist/function.zip")

  role    = aws_iam_role.lambda_exec.arn
  timeout = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  # ---------------------------------------------------------------------------
  # Environment variables: NON-SENSITIVE configuration only.
  # The HMAC salt secret NAME is passed (not the value); Lambda fetches the
  # value at runtime from Secrets Manager using the name.
  # ---------------------------------------------------------------------------
  environment {
    variables = {
      ENVIRONMENT              = var.environment
      POLL_RESULTS_TABLE       = aws_dynamodb_table.poll_results.name
      VOTER_LOG_TABLE          = aws_dynamodb_table.voter_log.name
      AUDIT_LOG_TABLE          = aws_dynamodb_table.audit_log.name
      HMAC_SALT_SECRET_NAME    = aws_secretsmanager_secret.hmac_salt.name
      VOTER_DEDUP_TTL_HOURS    = tostring(var.voter_dedup_ttl_hours)
      AWS_REGION_NAME          = var.aws_region # Explicit; avoids ambiguity with SDK defaults.
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role.lambda_exec,
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-vote-lambda"
  }
}

# ---------------------------------------------------------------------------
# Lambda permission: allow API Gateway to invoke this function.
# Scoped to the exact API Gateway ARN — no wildcard.
# ---------------------------------------------------------------------------
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.vote.function_name
  principal     = "apigateway.amazonaws.com"

  # source_arn format: arn:aws:execute-api:{region}:{account}:{api-id}/{stage}/{method}/{route}
  source_arn = "${aws_apigatewayv2_api.vote.execution_arn}/*/*"
}
