# Vote-on-It — Project Intelligence

This file is the authoritative context document for this project. Every Claude Code
session working on this codebase **must** read and adhere to everything here before
writing or modifying any code or infrastructure.

---

## 1. Project Overview

**Vote-on-It** is a simple, serverless polling application. A single question is
presented with 4 answer options. Users click an option; the page updates to show
live vote percentages rendered as a bar chart (Chart.js).

### User Flow
1. User lands on the CloudFront URL → sees a question with 4 buttons.
2. User clicks a button → `POST /vote` is called → DynamoDB counter atomically
   incremented → `GET /results` is called → bar chart replaces buttons.
3. On subsequent visits (same browser), `localStorage` prevents re-voting. The
   server-side `VoterLog` table provides a second dedup layer.

---

## 2. Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Static HTML + CSS + JavaScript (Chart.js for bar chart) |
| CDN / Hosting | AWS CloudFront + S3 (private bucket, OAC) |
| API | AWS API Gateway v2 (HTTP API) |
| Compute | AWS Lambda — single Go binary (`provided.al2023`, arm64) |
| Database | AWS DynamoDB (3 tables — see §6) |
| Secrets | AWS Secrets Manager |
| Infrastructure | Terraform ≥ 1.6.0 (HashiCorp AWS provider ~5.0) |
| Language | Go (Lambda backend) |

---

## 3. Mandatory Compliance Constraints (SOC2 & GDPR)

These are **non-negotiable** for the entire lifetime of this project. Never violate
them, and flag any proposed change that would conflict.

### 3.1 Auditability (SOC2)
- Every state change (`VOTE_CAST`, `DUPLICATE_VOTE_REJECTED`, `RESULTS_READ`) **must**
  write a structured record to the `AuditLog` DynamoDB table.
- Required fields: `EventID` (UUID v4), `Timestamp` (ISO-8601), `ActorID`
  (VoterHash or `"system"`), `Action` (string enum), `ResourceID`
  (`"PollID#<id>"`), `Outcome` (`"SUCCESS"` | `"FAILURE"`).
- The Lambda IAM role has **only** `dynamodb:PutItem` on AuditLog — no update or
  delete. The table is append-only by design.

### 3.2 PII Handling & Masking (GDPR)
- **Never** write a raw IP address to any log, database, or environment variable.
- IP addresses are pseudonymised via `HMAC-SHA256(rawIP + PollID, salt)` where
  `salt` is fetched from AWS Secrets Manager at Lambda cold-start.
- The resulting `VoterHash` is the only voter identifier stored server-side.
- In application logs (CloudWatch), use the `VoterHash` (first 8 chars for
  readability) — never the raw IP. Mask any other PII similarly
  (e.g., `j***@email.com`).

### 3.3 Right to be Forgotten (GDPR Article 17)
- User data is limited to the `VoterLog` table (pseudonymised hashes + TTL).
- Deleting a `VoterHash` item from `VoterLog` constitutes complete erasure for
  that voter fingerprint — no other table references them.
- `VoterLog` items have a DynamoDB TTL (`ExpiresAt`) of 24 hours (configurable
  via `var.voter_dedup_ttl_hours`). They are auto-purged by DynamoDB after expiry.

### 3.4 Encryption at Rest
- **All three DynamoDB tables** have `server_side_encryption { enabled = true }`.
- Both S3 buckets have SSE-S3 (AES-256) enforced.
- The S3 bucket policy includes a `Deny` statement for non-TLS requests.

---

## 4. Security Requirements

### 4.1 Secrets
- The HMAC salt lives **only** in AWS Secrets Manager (`vote-on-it/{env}/hmac-salt`).
- Lambda reads it once at cold-start and caches in memory for the instance lifetime.
- No credentials, tokens, or salts appear in environment variables, code, or
  Terraform state values. The secret **name** (not value) is passed as an env var.

### 4.2 IAM Least Privilege
- **No `*` resource ARNs** anywhere in `iam.tf` or any inline policy.
- Lambda role permissions are split into four separate inline policies:
  - `cloudwatch-logs` — write to its own log group only.
  - `dynamo-poll-results` — `GetItem`, `Scan`, `UpdateItem` on PollResults only.
  - `dynamo-voter-log` — `GetItem`, `PutItem` on VoterLog only.
  - `dynamo-audit-log-append-only` — `PutItem` on AuditLog only.
  - `secrets-manager-hmac-salt` — `GetSecretValue` on the exact secret ARN only.
- The S3 bucket policy allows `s3:GetObject` only from the specific CloudFront
  distribution ARN (prevents confused-deputy attacks from other CF distributions).

### 4.3 Input Validation
- All Lambda handlers validate request bodies against strict Go structs before
  processing. Unknown fields are rejected.
- The `option` field in `POST /vote` must be one of: `"A"`, `"B"`, `"C"`, `"D"`.
- The `poll_id` field must match the pattern `^poll-[a-z0-9-]{1,50}$`.
- All inputs are treated as hostile. No raw user input is interpolated into
  DynamoDB expressions — always use `ExpressionAttributeValues`.

### 4.4 Execution Safety
- **Never run `terraform apply`, `terraform destroy`, or `aws lambda update-function-code`**
  without explicit human confirmation in the session.
- `terraform fmt` and `terraform validate` are safe to run read-only.
- `terraform plan` is safe — it makes no mutations.

---

## 5. Architectural Rules

### 5.1 Layer Separation (Go Lambda)
```
cmd/main.go              — Entrypoint. Route dispatch only. No business logic.
internal/handler/        — HTTP layer: parse event, validate input, call service, return response.
internal/service/        — Business logic: dedup check, vote increment, audit log call.
internal/repository/     — Data access: DynamoDB reads/writes. No business logic.
internal/audit/          — Audit log writer. Called from service layer, not handler.
internal/model/          — Shared structs: request/response types, DynamoDB item shapes.
```
- **Handlers** must not call the repository directly. They call the service.
- **Services** must not know about HTTP (no `events.APIGatewayV2HTTPRequest` types).
- **Repositories** must not log or validate — they only read/write DynamoDB.

### 5.2 Statelessness
- Lambda instances are ephemeral. No in-memory state persists across invocations
  (except the cached HMAC salt, which is idempotent to re-fetch).
- All state lives in DynamoDB.

### 5.3 Error Handling
- All handlers return a standardised JSON error envelope:
  ```json
  { "error": { "code": "VOTE_ALREADY_CAST", "message": "You have already voted." } }
  ```
- Internal errors (`500`) return a generic message only — no stack traces, no
  internal resource names, no DynamoDB error details.
- HTTP status codes follow REST conventions: `200`, `400`, `409`, `429`, `500`.

### 5.4 CORS
- Allowed origin is locked to the CloudFront distribution domain (`https://<cf-domain>`).
- No wildcard (`*`) origins are permitted.

---

## 6. DynamoDB Schema

### `PollResults` — vote counters
| Attribute | Type | Notes |
|---|---|---|
| `PollID` (PK) | S | e.g. `"poll-2026-001"` |
| `OptionA` | N | Atomic ADD counter |
| `OptionB` | N | Atomic ADD counter |
| `OptionC` | N | Atomic ADD counter |
| `OptionD` | N | Atomic ADD counter |
| `CreatedAt` | S | ISO-8601, set on first write |

### `VoterLog` — deduplication (pseudonymised, no PII)
| Attribute | Type | Notes |
|---|---|---|
| `VoterHash` (PK) | S | `HMAC-SHA256(IP+PollID, salt)` — hex string |
| `PollID` (SK) | S | Enables per-poll dedup queries |
| `ExpiresAt` | N | Unix epoch; DynamoDB TTL attribute |

### `AuditLog` — SOC2 immutable audit trail
| Attribute | Type | Notes |
|---|---|---|
| `EventID` (PK) | S | UUID v4 |
| `Timestamp` (SK) | S | ISO-8601 |
| `ActorID` | S | `VoterHash[0:8]` or `"system"` |
| `Action` | S | Enum: `VOTE_CAST`, `RESULTS_READ`, `DUPLICATE_VOTE_REJECTED` |
| `ResourceID` | S | `"PollID#poll-2026-001"` |
| `Outcome` | S | `"SUCCESS"` or `"FAILURE"` |

---

## 7. Infrastructure Overview (Terraform)

All Terraform lives in `terraform/`. **Never run apply without human confirmation.**

| File | Responsibility |
|---|---|
| `main.tf` | Provider config, default tags, backend block (commented — enable for prod) |
| `variables.tf` | All input variables with validation rules |
| `dynamodb.tf` | 3 DynamoDB tables (PollResults, VoterLog, AuditLog) |
| `iam.tf` | Lambda execution role + 5 least-privilege inline policies |
| `secrets.tf` | Secrets Manager secret for HMAC salt; random salt generation |
| `lambda.tf` | Go Lambda function + CloudWatch log group + API GW invoke permission |
| `api_gateway.tf` | HTTP API v2, 2 routes (`POST /vote`, `GET /results`), throttling, access logs |
| `s3.tf` | Frontend bucket (private + OAC) + access-logs bucket |
| `cloudfront.tf` | CloudFront distribution + OAC + security response headers policy |
| `outputs.tf` | CloudFront URL, API URL, bucket name, table names, function name |

### Key Design Decisions
- **CloudFront → S3 via OAC** (not OAI — OAI is legacy).
- **`PriceClass_100`** restricts edge locations to US + EU (GDPR data-residency hint).
- **API Gateway v2 (HTTP API)** over REST API for lower latency and cost.
- **ARM64 / Graviton2** Lambda runtime (`provided.al2023`) — cheaper + faster for Go.
- **GDPR region validation** in `variables.tf` — only `eu-*` regions are accepted.
- **SOC2 log retention** — 365 days on all CloudWatch log groups.

---

## 8. Project Directory Structure

```
vote-on-it/
├── CLAUDE.md                  ← THIS FILE — read before anything else
├── terraform/                 ← All AWS infrastructure (Terraform)
│   ├── main.tf
│   ├── variables.tf
│   ├── dynamodb.tf
│   ├── iam.tf
│   ├── secrets.tf
│   ├── lambda.tf
│   ├── api_gateway.tf
│   ├── s3.tf
│   ├── cloudfront.tf
│   └── outputs.tf
├── lambda/                    ← Go Lambda (TO BE BUILT)
│   ├── cmd/
│   │   └── main.go
│   ├── internal/
│   │   ├── handler/
│   │   │   ├── vote.go
│   │   │   └── results.go
│   │   ├── service/
│   │   │   └── poll.go
│   │   ├── repository/
│   │   │   └── dynamo.go
│   │   ├── audit/
│   │   │   └── logger.go
│   │   └── model/
│   │       └── types.go
│   ├── go.mod
│   └── dist/                  ← Build output (git-ignored); contains function.zip
└── frontend/                  ← Static assets (TO BE BUILT)
    ├── index.html
    ├── style.css
    └── app.js
```

---

## 9. Build & Deploy Sequence (Manual — No Automation Yet)

**Do not run these without explicit confirmation. They are reference only.**

```bash
# 1. Build the Go Lambda binary
cd lambda
GOOS=linux GOARCH=arm64 go build -o dist/bootstrap ./cmd/...
zip -j dist/function.zip dist/bootstrap

# 2. Plan infrastructure (safe — read-only)
cd terraform
terraform init
terraform plan

# 3. Apply infrastructure (REQUIRES HUMAN CONFIRMATION)
terraform apply

# 4. Deploy frontend assets (after apply — bucket name from outputs)
aws s3 sync ../frontend/ s3://$(terraform output -raw frontend_bucket_name)/

# 5. Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id $(terraform output -raw cloudfront_distribution_id) \
  --paths "/*"
```

---

## 10. Current Build Status

| Component | Status |
|---|---|
| Terraform infrastructure | ✅ Complete — all `.tf` files written, not yet applied |
| Go Lambda backend | 🔲 Not started |
| Frontend (HTML/JS) | 🔲 Not started |

---

## 11. Checklist — Before Any Code Commit

- [ ] No raw IP address logged or stored anywhere
- [ ] No credentials or secrets hardcoded or in env vars (only secret **names**)
- [ ] Every state-changing Lambda path writes to AuditLog
- [ ] All DynamoDB writes use `ExpressionAttributeValues` (no string interpolation)
- [ ] Error responses contain no stack traces or internal resource identifiers
- [ ] Any new IAM statement has a specific resource ARN — no `*`
- [ ] Any new DynamoDB table has `server_side_encryption { enabled = true }`
