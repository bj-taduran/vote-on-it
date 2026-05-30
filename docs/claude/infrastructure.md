# Infrastructure & Deployment Detail

> Read this when working on Terraform, IAM policies, the build/deploy sequence, or
> infrastructure design decisions. The non-negotiable rules in `CLAUDE.md` still apply.

---

## Terraform File Map

| File | Responsibility |
|---|---|
| `main.tf` | AWS provider (`eu-*` region), `aws.us_east_1` alias (WAF only), default resource tags |
| `variables.tf` | All input variables with validation — rejects non-`eu-*` regions at plan time |
| `outputs.tf` | CloudFront URL, API URL, bucket name, table names, function name |
| `kms.tf` | Customer-managed CMK + alias + key policy (annual rotation enabled) |
| `dynamodb.tf` | `PollResults`, `VoterLog` (TTL + PITR), `AuditLog` (PITR) |
| `iam.tf` | Lambda execution role + 7 least-privilege inline policies (see below) |
| `secrets.tf` | Secrets Manager secret for HMAC salt + random salt generation |
| `lambda.tf` | Go Lambda function, code signing config, CloudWatch log group |
| `api_gateway.tf` | HTTP API v2, Lambda integration, 2 routes, throttling, access log group |
| `s3.tf` | Frontend bucket (private + OAC), access-logs bucket (lifecycle rules) |
| `cloudfront.tf` | CloudFront distribution, OAC, security response headers policy |
| `waf.tf` | WAFv2 WebACL (us-east-1), 3 managed rule groups, logging config |

---

## IAM Policies — Lambda Execution Role (7 inline policies)

| Policy | Permissions | Resource scope |
|---|---|---|
| `cloudwatch-logs` | `CreateLogGroup`, `CreateLogStream`, `PutLogEvents` | Lambda's own log group ARN only |
| `dynamo-poll-results` | `GetItem`, `Scan`, `UpdateItem` | `PollResults` table ARN only |
| `dynamo-voter-log` | `GetItem`, `PutItem` | `VoterLog` table ARN only |
| `dynamo-audit-log-append-only` | `PutItem` only | `AuditLog` table ARN only |
| `secrets-manager-hmac-salt` | `GetSecretValue` | Exact HMAC salt secret ARN only |
| `kms-cmk` | `kms:Decrypt`, `kms:GenerateDataKey` | Exact CMK ARN only |
| `xray` | `PutTraceSegments`, `PutTelemetryRecords` | `*` — X-Ray does not support resource-level restriction |

No `*` resource ARNs except X-Ray, which has no resource-scoping support in AWS.

---

## Build & Deploy Sequence

**Never run `apply` or `destroy` without explicit human confirmation.**

```bash
# 1. Build the Go Lambda binary (from project root)
cd lambda
GOOS=linux GOARCH=arm64 go build -o dist/bootstrap ./cmd/...
zip -j dist/function.zip dist/bootstrap

# 2. Plan infrastructure (safe — read-only)
cd terraform
terraform init
terraform plan

# 3. Apply (REQUIRES HUMAN CONFIRMATION)
terraform apply

# 4. Inject deployed API URL into frontend config
API_URL=$(cd terraform && terraform output -raw api_gateway_url)
sed -i "s|https://YOUR_API_GATEWAY_URL|$API_URL|" frontend/index.html

# 5. Deploy frontend assets
aws s3 sync frontend/ s3://$(cd terraform && terraform output -raw frontend_bucket_name)/

# 6. Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id $(cd terraform && terraform output -raw cloudfront_distribution_id) \
  --paths "/*"
```

---

## Key Design Decisions

- **CloudFront → S3 via OAC** (not OAI — OAI is legacy AWS practice).
- **`PriceClass_100`** — US + EU edge nodes only; aligns with GDPR data-residency intent.
- **API Gateway v2 (HTTP API)** — lower latency and cost than REST API.
- **ARM64 / Graviton2** Lambda (`provided.al2023`) — cheaper and faster for Go.
- **Single Lambda binary** for both routes (`POST /vote`, `GET /results`) — minimises cold-start surface.
- **DynamoDB TransactWriteItems** — VoterLog conditional `Put` + PollResults atomic `ADD` in one ACID call. No TOCTOU window between dedup check and counter increment.
- **GDPR region validation** in `variables.tf` — non-`eu-*` regions are rejected at plan time.
- **SOC2 log retention** — 365-day CloudWatch retention on all log groups; S3 audit logs transition to Glacier after 90 days, expire at the retention boundary.
- **WAF in us-east-1** — WAFv2 for CloudFront distributions must be provisioned in `us-east-1`. A provider alias (`aws.us_east_1`) handles this. WAF logs cannot use the `eu-central-1` CMK — this is an AWS constraint, not a security gap.
- **Code signing** — Lambda code signing is configured via AWS Signer (`AWSLambda-SHA384-ECDSA`). Set `untrusted_artifact_on_deployment = "Enforce"` once CI/CD signs artifacts.
- **`reserved_concurrent_executions`** — defined in `variables.tf` but commented out in dev; the account concurrency quota is too low to reserve executions while maintaining the mandatory 10-unit unreserved pool. Re-enable before production after a quota increase.

---

## CI Security Gate

Five jobs run in parallel on every PR targeting `main` (`.github/workflows/security-gate.yml`):

| Job | Tool | Threshold |
|---|---|---|
| SAST | gosec v2.21.4 | HIGH severity AND HIGH confidence (intersection filter) |
| SCA | govulncheck v1.1.3 | CVSS ≥ 7.0 — call-graph reachability analysis applied |
| IaC | checkov v3.2.351 | 14-check allowlist in `.checkov.yaml` (SOC2/GDPR controls only) |
| Secrets | TruffleHog v3.88.1 | Any verified secret fails the build immediately |
| Unit tests | `go test` | ≥ 80% statement coverage (current: 98%) |

The checkov allowlist approach is intentional — new Checkov rules never silently enter
the gate; they must be consciously added to `.checkov.yaml`.
