##############################################################################
# kms.tf — Customer-managed KMS key (CMK) for at-rest encryption.
#
# Compliance notes:
#   - SOC2:  CMK usage is auditable via CloudTrail (key-usage events).
#             Annual key rotation is enabled per SOC2 key-management controls.
#   - GDPR:  VoterLog and Secrets Manager (HMAC salt) are protected by this CMK.
#             Revoking the key constitutes cryptographic erasure of all data
#             encrypted with it — a valid GDPR Article 17 mechanism.
#
# Key policy design:
#   - Root delegation allows IAM policies to grant/restrict usage without
#     modifying this policy on every IAM change (stable, least-disruption).
#   - Service principals (CloudWatch Logs, Secrets Manager, Lambda) receive
#     explicit grants because IAM delegation alone is insufficient for
#     service-linked encryption contexts.
##############################################################################

resource "aws_kms_key" "main" {
  description             = "CMK for ${var.project_name}-${var.environment}: DynamoDB, Secrets Manager, Lambda env vars, CloudWatch Logs."
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.kms_key_policy.json

  tags = {
    Name         = "${var.project_name}-${var.environment}-cmk"
    DataClass    = "Key"
    GDPRRelevant = "true"
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.project_name}-${var.environment}"
  target_key_id = aws_kms_key.main.key_id
}

data "aws_iam_policy_document" "kms_key_policy" {
  # Root delegation — allows IAM policies in this account to grant key usage.
  # Without this, ALL grants must live in this key policy.
  statement {
    sid    = "AllowRootAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # CloudWatch Logs requires an explicit key policy grant. The service uses a
  # service-linked encryption context that IAM delegation cannot satisfy.
  statement {
    sid    = "AllowCloudWatchLogsEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }

  # Lambda service needs this CMK to decrypt environment variables at invocation.
  statement {
    sid    = "AllowLambdaEnvVarEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
  }

  # Secrets Manager uses this CMK to encrypt the HMAC salt secret.
  statement {
    sid    = "AllowSecretsManagerEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
  }
}
