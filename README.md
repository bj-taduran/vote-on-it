# vote-on-it

A serverless, single-question polling application built on AWS. Users land on a CloudFront-hosted page, click one of four answer options, and instantly see live vote percentages rendered as a CSS bar chart. The entire stack — compute, storage, CDN, and security controls — is managed as code using Terraform.

---

## Table of Contents

- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Security & Compliance](#security--compliance)
  - [SOC2 Controls](#soc2-controls)
  - [GDPR Controls](#gdpr-controls)
- [Security Guardrails & CI Checks](#security-guardrails--ci-checks)
  - [Pre-Merge Scanner Tuning](#pre-merge-scanner-tuning)
- [Infrastructure Overview](#infrastructure-overview)
- [Build Status](#build-status)

---

## Architecture

```
Browser
  │
  ▼
CloudFront (PriceClass_100 — US + EU edges)
  │   └─ WAFv2 WebACL (OWASP, Log4j, IP reputation)
  │   └─ Response Headers Policy (CSP, HSTS, X-Frame-Options)
  │
  ├──► S3 (private, OAC) — static frontend (HTML, CSS, JS)
  │
  └──► API Gateway v2 (HTTP API)
         └─ POST /vote  ─┐
         └─ GET /results ─┤
                          ▼
                    Lambda (Go, arm64)
                    ├─ Dedup check  → DynamoDB: VoterLog   (HMAC hash + TTL)
                    ├─ Vote counter → DynamoDB: PollResults (atomic ADD)
                    ├─ Audit write  → DynamoDB: AuditLog   (append-only)
                    └─ HMAC salt    ← Secrets Manager
```

**User flow:**
1. User visits the CloudFront URL → browser generates an anonymous UUID v4, stores it in `localStorage`.
2. User clicks a button → `POST /vote` is called with `{poll_id, option, voter_id}`.
3. Lambda HMAC-SHA256s the UUID + PollID with a server-side salt (never touches raw IP addresses).
4. A DynamoDB Transaction atomically records the voter hash in `VoterLog` (conditional — fails if already present) and increments the counter in `PollResults` using an atomic `ADD`.
5. On a successful vote (or server-side duplicate detection), `GET /results` is called and vote percentages are rendered as a CSS bar chart.
6. `localStorage` prevents client-side re-voting; `VoterLog` (server-side pseudonymised hash) is the deduplication source of truth.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Static HTML + CSS + Vanilla JavaScript (CSS bar chart — no JS framework) |
| CDN / Hosting | AWS CloudFront + S3 (private bucket, OAC) |
| Perimeter Security | AWS WAFv2 (OWASP, Log4j, IP reputation managed rules) |
| API | AWS API Gateway v2 (HTTP API) |
| Compute | AWS Lambda — Go binary (`provided.al2023`, arm64 / Graviton2) |
| Database | AWS DynamoDB — 3 tables (PollResults, VoterLog, AuditLog) |
| Encryption | AWS KMS CMK — DynamoDB, Secrets Manager, Lambda env vars, CloudWatch Logs |
| Secrets | AWS Secrets Manager (HMAC-SHA256 salt for voter pseudonymisation) |
| Infrastructure | Terraform ≥ 1.6.0 (HashiCorp AWS provider ~5.0) |
| Backend Language | Go 1.18+ |

---

## Project Structure

```
vote-on-it/
├── CLAUDE.md                        ← Authoritative project context for AI sessions
├── README.md                        ← This file
├── .github/
│   └── workflows/
│       └── security-gate.yml        ← CI security pipeline (gosec, govulncheck, checkov, TruffleHog)
├── .checkov.yaml                    ← Checkov allowlist (14 HIGH/CRITICAL IaC checks)
├── .gosec.json                      ← gosec per-rule tuning (extended G101 for HMAC secrets)
├── terraform/                       ← All AWS infrastructure (Terraform)
│   ├── main.tf                      ← Provider config, us-east-1 alias (WAF)
│   ├── variables.tf                 ← All input variables with validation
│   ├── outputs.tf                   ← CloudFront URL, API URL, table names, etc.
│   ├── kms.tf                       ← Customer-managed KMS key (CMK) + key policy
│   ├── dynamodb.tf                  ← PollResults, VoterLog (TTL), AuditLog (PITR) tables
│   ├── iam.tf                       ← Lambda execution role + 7 least-privilege inline policies
│   ├── secrets.tf                   ← Secrets Manager secret for HMAC salt
│   ├── lambda.tf                    ← Go Lambda function + code signing config
│   ├── api_gateway.tf               ← HTTP API v2, routes, throttling, access logs
│   ├── s3.tf                        ← Frontend bucket + access-logs bucket
│   ├── cloudfront.tf                ← CloudFront distribution + OAC + security headers
│   └── waf.tf                       ← WAFv2 WebACL + logging configuration
├── lambda/                          ← Go Lambda source
│   ├── cmd/
│   │   └── main.go                  ← Cold-start init, route dispatch, panic recovery
│   ├── internal/
│   │   ├── handler/                 ← HTTP layer: parse, validate, call service
│   │   │   ├── vote.go              ← POST /vote handler
│   │   │   ├── results.go           ← GET /results handler
│   │   │   └── helpers.go           ← Shared response builders, poll_id regex
│   │   ├── service/                 ← Business logic: HMAC, dedup, vote, results
│   │   │   └── poll.go
│   │   ├── repository/              ← DynamoDB reads/writes — no business logic
│   │   │   └── dynamo.go
│   │   ├── audit/                   ← Audit log writer (DynamoDB + CloudWatch)
│   │   │   └── logger.go
│   │   └── model/                   ← Shared request/response/DynamoDB types
│   │       └── types.go
│   ├── go.mod
│   ├── go.sum
│   └── dist/                        ← Build output — git-ignored (bootstrap, function.zip)
└── frontend/                        ← Static assets
    ├── index.html                   ← Shell with deploy-time API config block
    ├── style.css                    ← CSS bar chart + responsive layout
    └── app.js                       ← UUID generation, vote POST, results rendering
```

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Terraform | ≥ 1.6.0 | Infrastructure provisioning |
| Go | ≥ 1.18 | Lambda function compilation |
| AWS CLI | ≥ 2.x | Asset deployment + cache invalidation |
| An AWS account | — | Target environment (EU region required) |

---

## Getting Started

> **Never run `terraform apply` or `terraform destroy` without explicit human confirmation.** `terraform plan` and `terraform fmt`/`validate` are safe read-only operations.

### 1. Configure AWS credentials

```bash
aws configure   # or export AWS_PROFILE=<profile>
```

Ensure the target region is an EU region (e.g. `eu-central-1`) — GDPR data-residency validation is enforced in `variables.tf`.

### 2. Build the Lambda binary

```bash
cd lambda
GOOS=linux GOARCH=arm64 go build -o dist/bootstrap ./cmd/...
zip -j dist/function.zip dist/bootstrap
```

### 3. Initialise and plan infrastructure

```bash
cd terraform
terraform init
terraform plan
```

### 4. Apply infrastructure (requires explicit confirmation)

```bash
terraform apply   # Review plan carefully before typing "yes"
```

### 5. Inject the API URL into the frontend config

Before uploading the frontend, replace the placeholder URL in `index.html` with the deployed API Gateway URL:

```bash
API_URL=$(cd terraform && terraform output -raw api_gateway_url)
sed -i "s|https://YOUR_API_GATEWAY_URL|$API_URL|" frontend/index.html
```

### 6. Deploy frontend assets

```bash
# Run from the project root after terraform apply
aws s3 sync frontend/ s3://$(cd terraform && terraform output -raw frontend_bucket_name)/

# Invalidate the CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id $(cd terraform && terraform output -raw cloudfront_distribution_id) \
  --paths "/*"
```

### 7. Get the application URL

```bash
cd terraform && terraform output cloudfront_url
```

---

## API Reference

All requests pass through CloudFront → API Gateway. CORS is locked to the CloudFront domain; no wildcard origins are permitted.

### `POST /vote`

Records a vote. Lambda HMAC-SHA256s the `voter_id` (a client UUID — no IP address is transmitted or stored) and atomically writes to both `VoterLog` and `PollResults` via a DynamoDB Transaction.

**Request body**
```json
{
  "poll_id":  "poll-2026-001",
  "option":   "A",
  "voter_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

| Field | Type | Constraints |
|---|---|---|
| `poll_id` | string | Must match `^poll-[a-z0-9-]{1,50}$` |
| `option` | string | Must be one of `"A"`, `"B"`, `"C"`, `"D"` |
| `voter_id` | string | Must be a valid lowercase UUID v4 (client-generated, anonymous) |

Unknown JSON fields are rejected (`DisallowUnknownFields`).

**Responses**

| Status | Code | Meaning |
|---|---|---|
| `200` | — | Vote recorded |
| `400` | `INVALID_JSON` / `INVALID_POLL_ID` / `INVALID_OPTION` / `INVALID_VOTER_ID` | Validation failure |
| `409` | `VOTE_ALREADY_CAST` | Voter hash already recorded (duplicate vote) |
| `500` | `INTERNAL_ERROR` | Internal error — no internal details returned |

All error responses follow the same envelope:
```json
{ "error": { "code": "VOTE_ALREADY_CAST", "message": "You have already voted." } }
```

---

### `GET /results`

Returns current vote counts for a poll.

**Query parameter:** `poll_id=poll-2026-001` (optional — defaults to `poll-2026-001`)

**Response `200`**
```json
{
  "poll_id": "poll-2026-001",
  "options": {
    "A": 42,
    "B": 17,
    "C": 8,
    "D": 33
  },
  "total": 100
}
```

---

## Security & Compliance

This project is designed to meet SOC2 Type II and GDPR requirements. Every constraint listed below is enforced in code — either in Terraform, in the Lambda handler, or in the CI security gate.

### SOC2 Controls

| Control Area | Implementation |
|---|---|
| **Auditability** | Every state change (`VOTE_CAST`, `DUPLICATE_VOTE_REJECTED`, `RESULTS_READ`) writes a structured JSON record to the `AuditLog` DynamoDB table containing: `EventID` (UUID v4), `Timestamp` (ISO-8601 UTC), `ActorID` (first 8 hex chars of VoterHash, or `"system"`), `Action` (enum), `ResourceID` (`"PollID#<id>"`), and `Outcome` (`"SUCCESS"` or `"FAILURE"`). Each event is simultaneously emitted as a structured CloudWatch log line for real-time alerting. |
| **Audit log immutability** | The Lambda IAM role has `dynamodb:PutItem` only on `AuditLog` — `UpdateItem` and `DeleteItem` are explicitly excluded from the inline policy. Point-in-time recovery (PITR) is enabled on all three tables. |
| **Atomic state changes** | `POST /vote` uses a `TransactWriteItems` call combining a conditional `Put` on `VoterLog` (fails if voter hash already exists) and an atomic `ADD` on `PollResults` — both writes commit or both roll back. There is no window in which a vote counter is incremented without the dedup record being written. |
| **Log retention** | All CloudWatch log groups are set to 365-day retention (`var.log_retention_days`). The access-logs S3 bucket transitions to Glacier after 90 days and expires at the retention boundary. |
| **Log encryption** | Lambda and API Gateway CloudWatch log groups are encrypted with the project KMS CMK (`kms.tf`). The WAF log group is in us-east-1 (WAFv2 CloudFront scope requirement); the project CMK is eu-* regional — encrypting it would require a separate us-east-1 CMK, which is disproportionate for WAF access logs alone. |
| **Encryption at rest** | All three DynamoDB tables use a customer-managed KMS CMK. Lambda environment variables are encrypted with the same CMK. The Secrets Manager HMAC salt secret uses the CMK. Both S3 buckets use SSE-S3 (AES-256). |
| **Key management** | Annual CMK key rotation is enabled. Key usage is auditable via CloudTrail. Key revocation constitutes cryptographic erasure of all CMK-encrypted data, which is the GDPR Art. 17 erasure mechanism for all pseudonymised voter records at once. |
| **IAM least privilege** | The Lambda execution role has 7 separate inline policies, each scoped to exact resource ARNs: CloudWatch Logs (its own log group only), DynamoDB PollResults (`GetItem`, `Scan`, `UpdateItem`), DynamoDB VoterLog (`GetItem`, `PutItem`), DynamoDB AuditLog (`PutItem` only), Secrets Manager (exact secret ARN), KMS (exact CMK ARN), X-Ray. No `*` resource ARNs on any policy. |
| **Input validation** | All Lambda handlers validate request bodies against strict Go structs with `DisallowUnknownFields()`. `poll_id` is validated against `^poll-[a-z0-9-]{1,50}$`. `option` must be one of `A`, `B`, `C`, `D`. `voter_id` must match a lowercase UUID v4 regex. All DynamoDB expressions use `ExpressionAttributeValues` — no raw user input is interpolated into expressions. |
| **Perimeter security** | AWS WAFv2 WebACL on CloudFront with three AWS Managed Rule Groups: `AWSManagedRulesCommonRuleSet` (OWASP Top 10), `AWSManagedRulesKnownBadInputsRuleSet` (Log4j, SSRF, Spring4Shell), `AWSManagedRulesAmazonIpReputationList`. WAF logs ship to a dedicated CloudWatch log group. |
| **API throttling** | API Gateway default route settings: 50-request burst limit, 20 rps sustained. `reserved_concurrent_executions` is defined in `variables.tf` but commented out in dev — the account concurrency quota is too low to reserve executions while maintaining the mandatory 10-unit unreserved pool. Re-enable before production after requesting a quota increase (see `lambda.tf` for the checklist). |
| **Supply chain** | Lambda code signing is configured via AWS Signer (`AWSLambda-SHA384-ECDSA`). Unsigned deployments are flagged; set `untrusted_artifact_on_deployment = "Enforce"` once CI/CD signs artifacts. |
| **Error handling** | All handlers catch errors globally. A deferred `recover()` in the dispatcher catches unexpected panics. All `500` responses return only `{"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred."}}` — no stack traces, no resource names, no DynamoDB error details are ever surfaced to the caller. |
| **Distributed tracing** | Lambda X-Ray Active tracing is enabled for end-to-end request visibility and SOC2 per-request evidence. |
| **TLS enforcement** | CloudFront enforces HTTPS (`redirect-to-https`). The S3 bucket policy `Deny`s all non-TLS requests. HSTS is injected via the CloudFront Response Headers Policy (max-age 1 year, `includeSubDomains`, `preload`). Production deployments should supply `var.acm_certificate_arn` to enable the `TLSv1.2_2021` minimum protocol version. |
| **Security response headers** | CloudFront Response Headers Policy injects: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`. |
| **No hard-coded secrets** | Zero credentials, tokens, or secret values appear in code, environment variables, or Terraform state outputs. The HMAC salt name (not value) is passed to Lambda as an env var; the value is fetched at cold-start from Secrets Manager and cached in-memory for the lifetime of the instance. |

### GDPR Controls

| Article / Principle | Implementation |
|---|---|
| **Art. 4(5) — Pseudonymisation** | Raw IP addresses are never transmitted, processed, or stored anywhere in the system. The client generates an anonymous UUID v4 on first load and stores it in `localStorage`. Lambda receives this UUID and pseudonymises it server-side as `HMAC-SHA256(voterID + pollID, salt)` where `salt` is fetched from Secrets Manager. The resulting `VoterHash` is the sole voter identifier — it is a one-way function that cannot be reversed to identify any individual. |
| **Art. 5(1)(e) — Storage limitation** | `VoterLog` items carry a DynamoDB TTL (`ExpiresAt`) of 24 hours (configurable via `var.voter_dedup_ttl_hours`). DynamoDB auto-purges expired items. No other table stores voter-linked data. |
| **Art. 17 — Right to erasure** | Deleting a `VoterHash` item from `VoterLog` constitutes complete erasure for that voter fingerprint — no other table references the hash. Because the hash is a one-way HMAC with a server-side salt, it cannot be linked back to the originating UUID. CMK key revocation constitutes cryptographic erasure of all CMK-protected data simultaneously. |
| **Art. 25 — Data minimisation by design** | The minimum possible data is collected: only a pseudonymised hash and the chosen option. No name, email, IP, device fingerprint, or other PII is collected. Application logs use the first 8 hex characters of `VoterHash` for readability — never the raw UUID or hash in full. |
| **Art. 32 — Security of processing** | All data at rest is encrypted (CMK for DynamoDB, Secrets Manager, Lambda env vars; AES-256 for S3). All data in transit uses TLS enforced at CloudFront and S3. WAF provides perimeter protection at the CloudFront edge. API Gateway throttling limits burst traffic. |
| **Data residency** | `var.aws_region` is validated in `variables.tf` to accept only `eu-*` regions — deployments to non-EU regions are blocked at `terraform plan` time. CloudFront is configured with `PriceClass_100` (US + EU edge locations), which limits edge processing to US and EU nodes while keeping all data storage in the configured EU region. |
| **No PII in logs** | CloudWatch log formats in `api_gateway.tf` explicitly omit `$context.identity.sourceIp`. Lambda structured logs use only `VoterHash[:8]` as the actor identifier. No raw UUID, no IP, and no device information appears in any log group. |

---

## Security Guardrails & CI Checks

Every pull request targeting `main` must pass the **Security Gate** workflow (`.github/workflows/security-gate.yml`) before merge. The pipeline runs five independent jobs in parallel.

### 1. SAST — gosec

- **Tool:** [`securego/gosec`](https://github.com/securego/gosec) v2.21.4
- **Config:** `.gosec.json` at the repo root (extended G101 pattern to catch HMAC secret inlining)
- **Scope:** All Go source files under `lambda/`
- **Threshold:** Fails on findings that are simultaneously **HIGH severity** (`-severity high`) **and HIGH confidence** (`-confidence high`) — the intersection eliminates the majority of false positives that would otherwise block merges on legitimate Go patterns
- **Excluded rules:** `G104` (unhandled errors — endemic in AWS SDK usage), `G107` (URL-from-variable — false positives with runtime endpoint construction), `G304`/`G306` (filesystem taint/permissions — Lambda has no filesystem writes), `G108` (pprof endpoint — Lambda has no HTTP server), `G115` (integer overflow — extremely noisy in Go 1.22+ with valid int/uint conversions)
- **Output:** SARIF uploaded to GitHub Security tab for inline annotation
- **Guard:** If Lambda source does not yet exist (`go.mod` absent), an empty SARIF is emitted and the step passes — the scan activates automatically once Go code is committed

### 2. SCA — govulncheck

- **Tool:** [`golang.org/x/vuln/govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) v1.1.3
- **Scope:** All Go modules under `lambda/`
- **Threshold:** Fails on **HIGH** (CVSS ≥ 7.0) or **CRITICAL** (CVSS ≥ 9.0) vulnerabilities — severity is evaluated from the Go vulnerability database (`database_specific.severity`) with a CVSS v3 fallback
- **Reachability analysis:** govulncheck uses call-graph analysis — it only reports a CVE if a vulnerable function is actually reachable from this codebase. The majority of CVEs in transitive dependencies are never reached and are therefore never reported
- **Output:** Findings printed as `::error::` annotations in the Actions log

### 3. IaC — checkov

- **Tool:** [`bridgecrewio/checkov`](https://www.checkov.io/) v3.2.351
- **Config:** `.checkov.yaml` at the repo root — **allowlist approach**: only the 14 check IDs listed in that file are evaluated; every other Checkov rule is silently skipped
- **Scope:** All Terraform files under `terraform/`
- **Pre-flight:** `terraform fmt -check -recursive` and `terraform validate` must pass before checkov runs
- **Threshold:** Allowlist contains only HIGH/CRITICAL SOC2/GDPR controls; `--soft-fail-on LOW,MEDIUM,INFO` is a belt-and-suspenders guard in case a lower-severity check is ever added to the YAML
- **Output:** SARIF uploaded to GitHub Security tab; CLI summary in the Actions log
- **Documented suppressions:** All `checkov:skip` annotations in Terraform files include a justification comment explaining why the control does not apply (design decision, circular dependency, AWS constraint, or GDPR conflict)

### 4. Secrets — TruffleHog



- **Tool:** [`trufflesecurity/trufflehog`](https://github.com/trufflesecurity/trufflehog) v3.88.1
- **Scope:** All commits introduced by the PR (`base → head` range)
- **Mode:** `--only-verified` — only reports secrets that can be confirmed against their respective service APIs, reducing false positives
- **Threshold:** Any verified secret found fails the build immediately

### 5. Unit Tests — Go

- **Runner:** `go test -count=1 -covermode=atomic ./...` across all packages under `lambda/`
- **Threshold:** Total statement coverage must be **≥ 80%** — the job fails with an error annotation if the threshold is not met
- **How coverage is measured:** `go tool cover -func=coverage.out` produces per-function breakdown; the `total:` line is parsed and compared via `awk` float arithmetic
- **Artifact:** `coverage.out` is uploaded as `go-coverage-report` on every run (7-day retention) so reviewers can inspect per-function detail without re-running locally
- **Guard:** If `go.mod` is absent (Lambda source not yet written), the job exits cleanly — mirrors the guard pattern used by the gosec job
- **Current coverage:** `internal/repository` 100%, `internal/audit` 100%, `internal/handler` 100%, `internal/service` 100%, `cmd` 94.1% (only `main()` and the `log.Fatalf` error paths in `init()` are unreachable in unit tests) — **98% total**

---

### Pre-Merge Scanner Tuning

The three scanners are tuned for **zero-noise, high-signal** operation. The philosophy is: a scanner that produces false-positive noise will be bypassed — by engineers adding blanket suppressions, by CI being ignored, or by the gate being removed entirely. A focused gate that only fires on genuine catastrophic-risk findings earns trust and stays in place.

#### Two-stage strategy

| Stage | Trigger | Behavior | Scanners |
|---|---|---|---|
| **Pre-Merge** | Every PR targeting `main` | **Blocking** — PR cannot merge until all jobs pass | gosec, govulncheck, checkov (allowlist), TruffleHog, Unit Tests (≥ 80%) |
| **Acceptance** | Post-merge / nightly | **Non-blocking** — findings create issues, not merge gates | Full checkov ruleset, gosec without excludes, DAST, dependency audit |

The pre-merge stage intentionally runs a strict subset of each scanner's full capability. Rules that are accurate but noisy, best-practice linting, or medium-severity informational findings are deferred to the Acceptance stage.

---

#### Checkov — IaC scanner (`.checkov.yaml`)

**Approach:** explicit allowlist (`check:` block) — only 14 check IDs run; everything else is silently skipped.

**Why allowlist instead of blocklist?** A blocklist (`--skip-check`) requires enumerating every noisy rule and grows unbounded as Checkov adds new rules. An allowlist is stable: new Checkov rules never silently enter the pre-merge gate; they must be consciously added.

| Check ID | What it enforces | SOC2 / GDPR control |
|---|---|---|
| `CKV_AWS_53` | S3 `block_public_acls = true` | GDPR Art. 32 — data exposure prevention |
| `CKV_AWS_54` | S3 `ignore_public_acls = true` | GDPR Art. 32 — data exposure prevention |
| `CKV_AWS_55` | S3 `block_public_policy = true` | GDPR Art. 32 — data exposure prevention |
| `CKV_AWS_56` | S3 `restrict_public_buckets = true` | GDPR Art. 32 — data exposure prevention |
| `CKV2_AWS_6` | S3 combined public-access block | GDPR Art. 32 — belt-and-suspenders for above four |
| `CKV_AWS_19` | S3 default server-side encryption | GDPR Art. 32 / SOC2 CC6.7 — encryption at rest |
| `CKV_AWS_119` | DynamoDB SSE enabled | GDPR Art. 32 / SOC2 CC6.7 — encryption at rest |
| `CKV_AWS_7` | KMS annual key rotation | SOC2 CC6.1 / NIST SP 800-57 — key lifecycle |
| `CKV_AWS_28` | DynamoDB PITR enabled | SOC2 CC7.3 — audit trail recoverability |
| `CKV_AWS_50` | Lambda X-Ray active tracing | SOC2 CC7.2 — distributed trace evidence chain |
| `CKV_AWS_76` | API Gateway access logging | SOC2 CC7.2 — pre-Lambda request record |
| `CKV_AWS_68` | CloudFront WAF WebACL attached | SOC2 CC6.6 — perimeter security |
| `CKV_AWS_86` | CloudFront access logging | SOC2 CC7.2 — edge forensic record |
| `CKV_AWS_45` | Lambda: no hardcoded env-var credentials | SOC2 CC6.1 / GDPR Art. 32 |

**Deliberately excluded categories** (deferred to Acceptance):
- Cross-region replication (`CKV_AWS_144`) — conflicts with GDPR EU-only data-residency
- SSE-KMS for S3 (`CKV_AWS_145`) — circular Terraform dependency with CloudFront OAC; SSE-S3 (AES-256) is GDPR-compliant
- S3 versioning on log bucket (`CKV_AWS_21`) — append-only audit log; versioning creates unbounded storage without recovery benefit
- CloudFront geo-restriction (`CKV_AWS_374`) — `PriceClass_100` is the chosen data-residency control
- CloudFront origin failover (`CKV_AWS_310`) — second S3 bucket in a different region would violate the GDPR EU-only constraint
- API Gateway route authorisation (`CKV_AWS_309`) — intentionally public polling endpoint; input validation and dedup are Lambda-enforced
- Lambda VPC placement (`CKV_AWS_117`) — disproportionate for this architecture; all service access is via AWS service endpoints

---

#### gosec — Go SAST scanner (`.gosec.json` + CLI flags)

**Approach:** severity × confidence filter — only findings that score **HIGH** on both axes enter the gate.

**Active rules** (everything not in the exclude list, severity=high + confidence=high):

| Rule | What it catches | Why it belongs in pre-merge |
|---|---|---|
| `G101` | Hardcoded credentials / HMAC secrets (extended pattern in `.gosec.json`) | Any inlined secret = immediate account or GDPR breach |
| `G103` | `unsafe` package usage | Memory safety violations; potential for arbitrary memory read/write |
| `G106` | SSH `InsecureIgnoreHostKey` | Disables host verification; trivial MITM attack |
| `G204` | Command injection via `exec.Command` | Arbitrary OS command execution |
| `G402` | TLS `InsecureSkipVerify = true` | Disables certificate validation; trivial MITM on all outbound calls |
| `G403` | RSA key size < 2048 bits | Factored by modern hardware; key compromise |
| `G501–G505` | Import of `crypto/md5`, DES, RC4, SHA-1 | Cryptographically broken; data integrity and confidentiality failure |

**Excluded rules** (too noisy or structurally inapplicable for Lambda):

| Rule | Why excluded |
|---|---|
| `G104` | Unhandled errors — AWS SDK usage legitimately ignores many return values (e.g., log write failures must not crash the handler) |
| `G107` | URL-from-variable to HTTP request — false positives when constructing AWS service endpoint URLs at runtime from environment variables |
| `G304` | File path as taint input — Lambda has no dynamic filesystem reads |
| `G306` | Poor file permissions on write — Lambda writes nothing to the filesystem |
| `G108` | pprof endpoint publicly accessible — Lambda has no HTTP server and cannot register `/debug/pprof` |
| `G115` | Integer overflow on type conversion — extremely noisy in Go 1.22+ for valid `int`→`int64` conversions; the compiler already catches genuine overflows |

---

#### govulncheck — Go dependency vulnerability scanner

**Approach:** no additional tuning needed. govulncheck applies **call-graph reachability analysis** by default — it only reports a CVE if a vulnerable function is actually called, directly or transitively, from this codebase's code paths. The workflow applies a **severity filter** as a second layer, evaluating the Go vulnerability database `database_specific.severity` field (CVSS v3 fallback), and only `HIGH` (≥ 7.0) or `CRITICAL` (≥ 9.0) findings fail the build.

**Key design decisions:**
- `govulncheck ./...` uses package-level scanning (the default) with reachability analysis applied. Never use `-scan module`, which reports all vulnerabilities regardless of reachability
- The severity filter is applied in a workflow Python script, not via a govulncheck flag, because govulncheck has no native severity threshold option
- `|| true` on the govulncheck invocation ensures the JSON file is always written (govulncheck exits non-zero on any finding), allowing the Python severity step to make the final pass/fail decision

---

### Pre-commit checklist (manual)

Before committing any change, verify:

- [ ] No raw IP address logged or stored anywhere
- [ ] No raw voter UUID logged or stored anywhere (only the HMAC hash)
- [ ] No credentials or secret values hardcoded or in environment variables (only secret **names**)
- [ ] Every state-changing Lambda path writes to `AuditLog`
- [ ] All DynamoDB writes use `ExpressionAttributeValues` — no string interpolation
- [ ] Error responses contain no stack traces or internal resource identifiers
- [ ] Any new IAM statement has a specific resource ARN — no `*`
- [ ] Any new DynamoDB table has `server_side_encryption { enabled = true }` with `kms_key_arn`

---

## Infrastructure Overview

All AWS infrastructure is defined in `terraform/`. The table below summarises each file's responsibility.

| File | Resources |
|---|---|
| `main.tf` | AWS provider (EU region), `aws.us_east_1` alias (WAF only), default resource tags |
| `variables.tf` | All input variables with validation rules and defaults |
| `outputs.tf` | CloudFront URL, API URL, bucket name, table names, function name |
| `kms.tf` | Customer-managed CMK + alias + key policy |
| `dynamodb.tf` | `PollResults`, `VoterLog` (TTL + PITR), `AuditLog` (PITR, append-only IAM) |
| `iam.tf` | Lambda execution role + 7 least-privilege inline policies |
| `secrets.tf` | Secrets Manager secret for HMAC salt + random salt generation |
| `lambda.tf` | Go Lambda function, code signing config, CloudWatch log group |
| `api_gateway.tf` | HTTP API v2, Lambda integration, 2 routes, throttling, access log group |
| `s3.tf` | Frontend bucket (private + OAC), access-logs bucket (lifecycle rules) |
| `cloudfront.tf` | CloudFront distribution, OAC, security response headers policy |
| `waf.tf` | WAFv2 WebACL (us-east-1), managed rules, logging configuration |

### Key design decisions

- **CloudFront → S3 via OAC** (not the legacy OAI) — current AWS best practice
- **`PriceClass_100`** restricts edge locations to US + EU for GDPR data-residency alignment
- **API Gateway v2 (HTTP API)** over REST API — lower latency and cost
- **ARM64 / Graviton2** Lambda runtime (`provided.al2023`) — cheaper and faster for Go
- **Single Lambda binary** handles both routes (`POST /vote`, `GET /results`) — minimises cold-start surface
- **DynamoDB Transaction** for atomic vote submission — VoterLog conditional Put + PollResults atomic ADD commit or roll back together, with no gap between dedup record and counter increment
- **GDPR region validation** in `variables.tf` — only `eu-*` regions are accepted at plan time
- **SOC2 log retention** — 365-day retention on all CloudWatch log groups; S3 audit logs transition to Glacier after 90 days

---

## Build Status

| Component | Status |
|---|---|
| Terraform infrastructure | ✅ Complete — all `.tf` files written; not yet applied to a live environment |
| Go Lambda backend | ✅ Complete — all layers implemented (`handler`, `service`, `repository`, `audit`, `model`); `go build` and `go vet` pass |
| Frontend (HTML/CSS/JS) | ✅ Complete — vanilla JS, CSS bar chart, UUID-based anti-spam, localStorage dedup |
| Security gate CI | ✅ Passing — gosec, govulncheck, checkov (0 hard-fail findings), TruffleHog |
