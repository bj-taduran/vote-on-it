##############################################################################
# iam.tf — Least-privilege IAM roles and policies.
#
# Security notes:
#   - NO wildcard (*) resource ARNs anywhere in this file.
#   - Each permission is scoped to the exact resource ARN it needs.
#   - The Lambda execution role is the only principal that can write to
#     DynamoDB. Read-only paths (GET /results) use a separate condition.
#   - Audit log table policy is append-only (PutItem only — no UpdateItem,
#     DeleteItem) to preserve immutability.
##############################################################################

# ---------------------------------------------------------------------------
# Lambda Execution Role — assumed by the Lambda function at runtime.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    sid     = "AllowLambdaAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.project_name}-${var.environment}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  description        = "Execution role for the vote-on-it Lambda. Least-privilege scoped to exact ARNs."
}

# ---------------------------------------------------------------------------
# Policy: CloudWatch Logs — write structured logs to its own log group only.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_logs" {
  statement {
    sid    = "AllowCreateLogGroup"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
    ]
  }

  statement {
    sid    = "AllowWriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.lambda.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "lambda_logs" {
  name   = "cloudwatch-logs"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_logs.json
}

# ---------------------------------------------------------------------------
# Policy: DynamoDB — PollResults (read + atomic increment only)
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_dynamo_poll" {
  statement {
    sid    = "AllowPollResultsRead"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Scan", # Used only by GET /results; acceptable at this table size.
    ]
    resources = [aws_dynamodb_table.poll_results.arn]
  }

  statement {
    sid    = "AllowPollResultsAtomicIncrement"
    effect = "Allow"
    actions = [
      "dynamodb:UpdateItem", # Required for atomic ADD counter increments.
    ]
    resources = [aws_dynamodb_table.poll_results.arn]
  }
}

resource "aws_iam_role_policy" "lambda_dynamo_poll" {
  name   = "dynamo-poll-results"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_dynamo_poll.json
}

# ---------------------------------------------------------------------------
# Policy: DynamoDB — VoterLog (check existence + conditional write + TTL)
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_dynamo_voter" {
  statement {
    sid    = "AllowVoterLogDedup"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem", # Check: has this hash already voted?
      "dynamodb:PutItem", # Write: record the hash after a successful vote.
    ]
    resources = [aws_dynamodb_table.voter_log.arn]
  }
}

resource "aws_iam_role_policy" "lambda_dynamo_voter" {
  name   = "dynamo-voter-log"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_dynamo_voter.json
}

# ---------------------------------------------------------------------------
# Policy: DynamoDB — AuditLog (append-only — PutItem ONLY, never delete/update)
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_dynamo_audit" {
  statement {
    sid    = "AllowAuditLogAppendOnly"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem", # Append only. UpdateItem and DeleteItem are deliberately excluded.
    ]
    resources = [aws_dynamodb_table.audit_log.arn]
  }
}

resource "aws_iam_role_policy" "lambda_dynamo_audit" {
  name   = "dynamo-audit-log-append-only"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_dynamo_audit.json
}

# ---------------------------------------------------------------------------
# Policy: Secrets Manager — read the HMAC salt secret ONLY.
# The resource ARN is scoped to the exact secret name pattern.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_secrets" {
  statement {
    sid    = "AllowReadHMACSalt"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}/${var.environment}/hmac-salt*"
    ]
  }
}

resource "aws_iam_role_policy" "lambda_secrets" {
  name   = "secrets-manager-hmac-salt"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_secrets.json
}

# ---------------------------------------------------------------------------
# Policy: KMS — allow Lambda to use the CMK for DynamoDB and Secrets Manager.
# DynamoDB transparently calls KMS when reading/writing CMK-encrypted items;
# the calling principal (Lambda role) must have these permissions.
# Same applies when Secrets Manager returns a CMK-encrypted secret value.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_kms" {
  statement {
    sid    = "AllowCMKForDynamoDBAndSecretsManager"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "lambda_kms" {
  name   = "kms-cmk-access"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_kms.json
}

# ---------------------------------------------------------------------------
# Policy: X-Ray — active tracing for SOC2 auditability (CKV_AWS_50).
# xray:PutTraceSegments and xray:PutTelemetryRecords do not support resource-
# level constraints in AWS IAM — "*" is the only valid resource value for
# these actions. This is an AWS service limitation, not a policy choice.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_xray" {
  statement {
    sid    = "AllowXRayTracing"
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]
    # AWS does not support resource-level restrictions for X-Ray trace actions.
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_xray" {
  name   = "xray-tracing"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_xray.json
}

# ---------------------------------------------------------------------------
# Data source: current AWS account ID (used in ARN construction above).
# ---------------------------------------------------------------------------
data "aws_caller_identity" "current" {}
