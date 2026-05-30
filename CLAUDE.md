# Vote-on-It — Project Intelligence

Authoritative orientation for every Claude Code session. Read this first, then read the
satellite file(s) listed in §6 **only for the area you are about to work in**.

---

## 1. What This Project Is

Serverless, single-question polling app on AWS. Browser → CloudFront + WAFv2 →
API Gateway v2 → Go Lambda → DynamoDB. All infrastructure is Terraform. All three
layers (Lambda, frontend, Terraform) are complete and passing CI.

**Stack:** Go (arm64 Lambda · `provided.al2023`) · DynamoDB (3 tables) ·
Terraform ≥ 1.6.0 · CloudFront + WAFv2 · KMS CMK · Secrets Manager

---

## 2. Non-Negotiable Rules

Apply to every file, every change. Flag any proposed change that conflicts.

### PII / GDPR
- **Never** write a raw IP address or raw voter UUID to any log, table, env var, or response.
- Voter identity = `HMAC-SHA256(voterID + pollID, salt)` → `VoterHash` (64-char hex). Only the hash is ever stored or logged.
- CloudWatch logs use `VoterHash[:8]` as the actor identifier — nothing more.

### Auditability (SOC2)
- Every state change (`VOTE_CAST`, `DUPLICATE_VOTE_REJECTED`, `RESULTS_READ`) **must** write to `AuditLog`.
- Required fields: `EventID` (UUID v4), `Timestamp` (ISO-8601 UTC), `ActorID`, `Action`, `ResourceID` (`"PollID#<id>"`), `Outcome` (`"SUCCESS"` | `"FAILURE"`).
- Lambda IAM has `dynamodb:PutItem` only on `AuditLog` — `UpdateItem`/`DeleteItem` are absent by design.

### IAM
- No `*` resource ARNs anywhere. Every policy statement targets an exact ARN.

### DynamoDB
- All writes use `ExpressionAttributeValues` — never interpolate user input into expressions.
- Every new table: `server_side_encryption { enabled = true }` with `kms_key_arn`.

### Secrets
- HMAC salt lives only in Secrets Manager. The secret **name** (not value) is passed as an env var.
- No credentials, tokens, or secret values in code, env vars, or Terraform state.

### Execution Safety
- **Never run `terraform apply`, `terraform destroy`, or `aws lambda update-function-code`** without explicit human confirmation.
- `terraform plan`, `terraform fmt`, `terraform validate` are safe (non-mutating).

### Error Responses
- `500` returns only `{"error":{"code":"INTERNAL_ERROR","message":"An unexpected error occurred."}}`.
- No stack traces, no internal ARNs, no DynamoDB error details in any response.

---

## 3. Go Lambda Layer Separation

```
cmd/main.go          — Cold-start init, route dispatch. No business logic.
internal/handler/    — HTTP layer: parse event, validate input, call service, return response.
internal/service/    — Business logic: HMAC, dedup, vote, audit. No HTTP types.
internal/repository/ — DynamoDB reads/writes only. No logging, no validation.
internal/audit/      — AuditLog writer. Called from service layer only.
internal/model/      — Shared structs. No logic.
```

- Handlers call the service, not the repository directly.
- Services must not import `events.APIGatewayV2HTTPRequest` or any HTTP type.
- Repositories do not log or validate — they only read/write DynamoDB.

---

## 4. Current Status

| Component | Status |
|---|---|
| Terraform infrastructure | ✅ Complete — not yet applied to a live environment |
| Go Lambda backend | ✅ Complete — all layers; 98% unit test coverage |
| Frontend (HTML/CSS/JS) | ✅ Complete — vanilla JS, CSS bar chart, UUID-based anti-spam |
| Security gate CI | ✅ Passing — gosec · govulncheck · checkov · TruffleHog · unit tests |
| Threat model (tachi) | ✅ First run complete — 42 findings (3 Critical, 8 High) in `docs/security/` |

---

## 5. Pre-Commit Checklist

- [ ] No raw IP or raw voter UUID logged or stored anywhere
- [ ] No credentials or secret values hardcoded or in env vars (only names)
- [ ] Every state-changing Lambda path writes to AuditLog
- [ ] All DynamoDB writes use `ExpressionAttributeValues`
- [ ] Error responses contain no stack traces or internal resource identifiers
- [ ] Any new IAM statement has a specific resource ARN — no `*`
- [ ] Any new DynamoDB table has `server_side_encryption { enabled = true }` with `kms_key_arn`

---

## 6. Satellite Context Files

Read the relevant file before starting work in that area. Do **not** read all of them
unconditionally — they exist to keep context focused, not to be loaded by default.

| Working on… | Read |
|---|---|
| Lambda Go code, DynamoDB schema, input validation, error handling, CORS, compliance detail | [`docs/claude/compliance.md`](docs/claude/compliance.md) |
| Terraform, IAM policies, build/deploy sequence, infrastructure design | [`docs/claude/infrastructure.md`](docs/claude/infrastructure.md) |
| Security findings, threat model output, re-running tachi, attack trees | [`docs/claude/threat-model.md`](docs/claude/threat-model.md) |
