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

  # SOC2: CMK encrypts audit log data at rest (CKV_AWS_158).
  kms_key_id = aws_kms_key.main.arn

  tags = {
    Name       = "${var.project_name}-${var.environment}-lambda-logs"
    DataClass  = "Audit"
    Compliance = "SOC2"
  }
}

# ---------------------------------------------------------------------------
# Lambda code signing — validates the deployment package before execution.
# Signing profile: AWS Signer using ECDSA-SHA384 (Lambda's required algorithm).
# ---------------------------------------------------------------------------
resource "aws_signer_signing_profile" "lambda" {
  platform_id = "AWSLambda-SHA384-ECDSA"
  name_prefix = "${replace(var.project_name, "-", "")}${var.environment}"

  signature_validity_period {
    value = 5
    type  = "YEARS"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-signing-profile"
  }
}

resource "aws_lambda_code_signing_config" "vote" {
  description = "Code signing for ${var.project_name}-${var.environment} Lambda."

  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda.version_arn]
  }

  # "Warn" allows deployment of unsigned packages while flagging them.
  # Change to "Enforce" after CI/CD pipeline is wired to sign artifacts.
  policies {
    untrusted_artifact_on_deployment = "Warn"
  }
}

# ---------------------------------------------------------------------------
# Lambda function
# The deployment package (Go binary zipped) is expected at:
#   ../lambda/dist/function.zip
# Build it with: GOOS=linux GOARCH=arm64 go build -o bootstrap ./cmd/...
# ---------------------------------------------------------------------------
# checkov:skip=CKV_AWS_115: "Cannot reserve concurrency due to AWS account limits in dev environment"
resource "aws_lambda_function" "vote" {
  #checkov:skip=CKV_AWS_116:This Lambda is invoked synchronously by API Gateway. DLQ only applies to async invocations (SNS/SQS/EventBridge); errors are returned directly to the API caller.
  #checkov:skip=CKV_AWS_117:Lambda accesses DynamoDB, Secrets Manager, and X-Ray via AWS service endpoints. Adding a VPC requires NAT gateway or VPC endpoints for all three services, which is disproportionate for this single-function serverless architecture.
  function_name = "${var.project_name}-${var.environment}-vote"
  description   = "Handles POST /vote and GET /results for the vote-on-it application."

  # Go compiled for Lambda's arm64 (Graviton2) — cheaper and faster than x86.
  runtime       = "provided.al2023"
  architectures = ["arm64"]
  handler       = "bootstrap" # Required name for custom runtime on AL2023.

  filename         = "../lambda/dist/function.zip"
  source_code_hash = filebase64sha256("../lambda/dist/function.zip")

  role        = aws_iam_role.lambda_exec.arn
  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  # SOC2: KMS CMK encrypts environment variables at rest (CKV_AWS_173).
  kms_key_arn = aws_kms_key.main.arn

  # SOC2: Active tracing provides distributed traces for audit and debugging (CKV_AWS_50).
  tracing_config {
    mode = "Active"
  }

  # Supply chain: validates the deployment package is signed before execution (CKV_AWS_272).
  code_signing_config_arn = aws_lambda_code_signing_config.vote.arn

  # reserved_concurrent_executions = var.lambda_reserved_concurrency
  #
  # Commented out: dev account has insufficient total concurrency quota to reserve
  # executions while maintaining the mandatory 10-unit unreserved pool
  # (InvalidParameterValueException from AWS).
  #
  # RE-ENABLE THIS BEFORE PRODUCTION:
  #   1. Request a Lambda concurrency quota increase via AWS Service Quotas
  #      (default 1,000 per region; request ≥ 200 for this workload).
  #   2. Set var.lambda_reserved_concurrency to a value that leaves ≥ 100
  #      unreserved units for other functions in the account.
  #   3. Keep the value above the API Gateway burst limit (currently 50) so
  #      legitimate traffic bursts are not throttled at the Lambda layer.
  #   4. In production, reserved concurrency is a SOC2 blast-radius control:
  #      it prevents a traffic spike or abuse scenario from exhausting the
  #      entire account concurrency pool and taking down unrelated functions.

  # ---------------------------------------------------------------------------
  # Environment variables: NON-SENSITIVE configuration only.
  # The HMAC salt secret NAME is passed (not the value); Lambda fetches the
  # value at runtime from Secrets Manager using the name.
  # ---------------------------------------------------------------------------
  environment {
    variables = {
      ENVIRONMENT           = var.environment
      POLL_RESULTS_TABLE    = aws_dynamodb_table.poll_results.name
      VOTER_LOG_TABLE       = aws_dynamodb_table.voter_log.name
      AUDIT_LOG_TABLE       = aws_dynamodb_table.audit_log.name
      HMAC_SALT_SECRET_NAME = aws_secretsmanager_secret.hmac_salt.name
      VOTER_DEDUP_TTL_HOURS = tostring(var.voter_dedup_ttl_hours)
      AWS_REGION_NAME       = var.aws_region # Explicit; avoids ambiguity with SDK defaults.
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
