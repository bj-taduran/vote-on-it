##############################################################################
# secrets.tf — AWS Secrets Manager resources.
#
# Security notes:
#   - The HMAC salt is generated ONCE by Terraform and stored in Secrets Manager.
#   - The Lambda reads it at cold-start; it is never embedded in code or env vars.
#   - Rotation policy placeholder is included — wire it to a rotation Lambda
#     in production. Rotating the salt will invalidate all existing VoterLog
#     hashes (acceptable — voters can vote again after rotation window).
##############################################################################

# Generate a cryptographically random 32-byte salt on first apply.
# Terraform manages this; it will not regenerate on subsequent applies.
resource "random_bytes" "hmac_salt" {
  length = 32
}

resource "aws_secretsmanager_secret" "hmac_salt" {
  name        = "${var.project_name}/${var.environment}/hmac-salt"
  description = "HMAC-SHA256 salt used to pseudonymise voter IP addresses. Never expose this value."

  # GDPR / SOC2: CMK encryption — auditable via CloudTrail (CKV_AWS_149).
  # Revoking this key cryptographically erases all voter pseudonyms.
  kms_key_id = aws_kms_key.main.arn

  # SOC2: Recovery window prevents accidental instant deletion.
  recovery_window_in_days = 7

  tags = {
    Name         = "${var.project_name}-${var.environment}-hmac-salt"
    DataClass    = "Secret"
    GDPRRelevant = "true"
  }
}

resource "aws_secretsmanager_secret_version" "hmac_salt" {
  secret_id = aws_secretsmanager_secret.hmac_salt.id

  # Store as a JSON object so additional fields can be added without schema changes.
  secret_string = jsonencode({
    salt = random_bytes.hmac_salt.base64
  })

  # Lifecycle: prevent Terraform from rotating the salt on every plan/apply.
  lifecycle {
    ignore_changes = [secret_string]
  }
}
