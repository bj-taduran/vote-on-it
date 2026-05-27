##############################################################################
# outputs.tf — Values needed by other pipeline stages or operators.
#
# Note: No secrets or sensitive ARNs are output here. The HMAC salt and any
# credentials remain in Secrets Manager only.
##############################################################################

output "cloudfront_url" {
  description = "The public URL of the vote-on-it frontend. Share this with users."
  value       = "https://${aws_cloudfront_distribution.frontend.domain_name}"
}

output "api_gateway_url" {
  description = "Base URL of the HTTP API. Used by the frontend to call POST /vote and GET /results."
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "frontend_bucket_name" {
  description = "S3 bucket name for deploying frontend assets (CI/CD use)."
  value       = aws_s3_bucket.frontend.bucket
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID — needed to invalidate the cache after a frontend deploy."
  value       = aws_cloudfront_distribution.frontend.id
}

output "poll_results_table_name" {
  description = "DynamoDB PollResults table name — passed to Lambda via environment variable."
  value       = aws_dynamodb_table.poll_results.name
}

output "voter_log_table_name" {
  description = "DynamoDB VoterLog table name."
  value       = aws_dynamodb_table.voter_log.name
}

output "audit_log_table_name" {
  description = "DynamoDB AuditLog table name."
  value       = aws_dynamodb_table.audit_log.name
}

output "lambda_function_name" {
  description = "Lambda function name — used by CI/CD to deploy new code versions."
  value       = aws_lambda_function.vote.function_name
}

output "hmac_salt_secret_name" {
  description = "Secrets Manager secret name for the HMAC salt (not the value)."
  value       = aws_secretsmanager_secret.hmac_salt.name
}
