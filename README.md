# vote-on-it

A serverless, single-question polling application built on AWS. Users land on a CloudFront-hosted page, click one of four answer options, and instantly see live vote percentages rendered as a bar chart. The entire stack — compute, storage, CDN, and security controls — is managed as code using Terraform.

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
                    ├─ Dedup check  → DynamoDB: VoterLog
                    ├─ Vote counter → DynamoDB: PollResults
                    ├─ Audit write  → DynamoDB: AuditLog
                    └─ HMAC salt    ← Secrets Manager
```

**User flow:**
1. User visits the CloudFront URL → sees a question with four answer buttons.
2. User clicks a button → `POST /vote` atomically increments a DynamoDB counter.
3. `GET /results` is called → vote percentages are rendered as a Chart.js bar chart.
4. `localStorage` prevents client-side re-voting; `VoterLog` (server-side pseudonymised hash) provides the deduplication source of truth.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Static HTML + CSS + JavaScript (Chart.js) |
| CDN / Hosting | AWS CloudFront + S3 (private bucket, OAC) |
| Perimeter Security | AWS WAFv2 (OWASP, Log4j, IP reputation managed rules) |
| API | AWS API Gateway v2 (HTTP API) |
| Compute | AWS Lambda — Go binary (`provided.al2023`, arm64 / Graviton2) |
| Database | AWS DynamoDB — 3 tables (PollResults, VoterLog, AuditLog) |
| Encryption | AWS KMS CMK — DynamoDB, Secrets Manager, Lambda env vars, CloudWatch Logs |
| Secrets | AWS Secrets Manager (HMAC-SHA256 salt for voter pseudonymisation) |
| Infrastructure | Terraform ≥ 1.6.0 (HashiCorp AWS provider ~5.0) |
| Backend Language | Go 1.23 |

---

## Project Structure

```
vote-on-it/
├── CLAUDE.md                        ← Authoritative project context for AI sessions
├── README.md                        ← This file
├── .github/
│   └── workflows/
│       └── security-gate.yml        ← CI security pipeline (gosec, govulncheck, checkov, TruffleHog)
├── terraform/                       ← All AWS infrastructure (Terraform)
│   ├── main.tf                      ← Provider config, us-east-1 alias (WAF)
│   ├── variables.tf                 ← All input variables with validation
│   ├── outputs.tf                   ← CloudFront URL, API URL, table names, etc.
│   ├── kms.tf                       ← Customer-managed KMS key (CMK) + key policy
│   ├── dynamodb.tf                  ← PollResults, VoterLog, AuditLog tables
│   ├── iam.tf                       ← Lambda execution role + 7 least-privilege policies
│   ├── secrets.tf                   ← Secrets Manager secret for HMAC salt
│   ├── lambda.tf                    ← Go Lambda function + code signing config
│   ├── api_gateway.tf               ← HTTP API v2, routes, throttling, access logs
│   ├── s3.tf                        ← Frontend bucket + access-logs bucket
│   ├── cloudfront.tf                ← CloudFront distribution + OAC + security headers
│   └── waf.tf                       ← WAFv2 WebACL + logging configuration
├── lambda/                          ← Go Lambda source (to be built)
│   ├── cmd/main.go
│   ├── internal/
│   │   ├── handler/                 ← HTTP layer (vote.go, results.go)
│   │   ├── service/                 ← Business logic (poll.go)
│   │   ├── repository/              ← DynamoDB reads/writes (dynamo.go)
│   │   ├── audit/                   ← Audit log writer (logger.go)
│   │   └── model/                   ← Shared types (types.go)
│   ├── go.mod
│   └── dist/                        ← Build output — git-ignored (function.zip)
└── frontend/                        ← Static assets (to be built)
    ├── index.html
    ├── style.css
    └── app.js
```

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Terraform | ≥ 1.6.0 | Infrastructure provisioning |
| Go | ≥ 1.23 | Lambda function compilation |
| AWS CLI | ≥ 2.x | Asset deployment + cache invalidation |
| An AWS account | — | Target environment (EU region required) |

---

## Getting Started

> **Never run `terraform apply` or `terraform destroy` without explicit human confirmation.** `terraform plan` and `terraform fmt`/`validate` are safe read-only operations.

### 1. Configure AWS credentials

```bash
aws configure   # or export AWS_PROFILE=<profile>
```

Ensure the target region is an EU region (e.g. `eu-west-1`, `eu-central-1`) — GDPR data-residency validation is enforced in `variables.tf`.

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

### 5. Deploy frontend assets

```bash
# Run from the project root after terraform apply
aws s3 sync frontend/ s3://$(cd terraform && terraform output -raw frontend_bucket_name)/

# Invalidate the CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id $(cd terraform && terraform output -raw cloudfront_distribution_id) \
  --paths "/*"
```

### 6. Get the application URL

```bash
cd terraform && terraform output cloudfront_url
```

---

## API Reference

All requests pass through CloudFront → API Gateway. CORS is locked to the CloudFront domain; no wildcard origins are permitted.

### `POST /vote`

Records a vote for the given poll and option.

**Request body**
```json
{
  "poll_id": "poll-2026-001",
  "option":  "A"
}
```

| Field | Type | Constraints |
|---|---|---|
| `poll_id` | string | Must match `^poll-[a-z0-9-]{1,50}$` |
| `option` | string | Must be one of `"A"`, `"B"`, `"C"`, `"D"` |

**Responses**

| Status | Meaning |
|---|---|
| `200` | Vote recorded |
| `400` | Invalid request body or unknown field |
| `409` | Voter hash already recorded (duplicate vote) |
| `500` | Internal error (no internal details returned) |

---

### `GET /results`

Returns current vote counts for a poll.

**Query parameter:** `poll_id=poll-2026-001`

**Response `200`**
```json
{
  "poll_id":  "poll-2026-001",
  "option_a": 42,
  "option_b": 17,
  "option_c": 8,
  "option_d": 33
}
```

---

## Security & Compliance

This project is designed to meet SOC2 Type II and GDPR requirements. Every constraint listed below is enforced in code — either in Terraform or in the Lambda handler.

### SOC2 Controls

| Control Area | Implementation |
|---|---|
| **Auditability** | Every state change (`VOTE_CAST`, `DUPLICATE_VOTE_REJECTED`, `RESULTS_READ`) writes a structured record to the `AuditLog` DynamoDB table with `EventID` (UUID v4), `Timestamp` (ISO-8601), `ActorID`, `Action`, `ResourceID`, and `Outcome`. |
| **Audit log immutability** | The Lambda IAM role has `dynamodb:PutItem` only on `AuditLog` — `UpdateItem` and `DeleteItem` are explicitly excluded. Point-in-time recovery (PITR) is enabled. |
| **Log retention** | All CloudWatch log groups are set to 365-day retention (`var.log_retention_days`). The access-logs S3 bucket transitions to Glacier after 90 days, expires at the retention boundary, and aborts incomplete multipart uploads after 7 days. |
| **Log encryption** | Lambda and API Gateway CloudWatch log groups are encrypted with the project KMS CMK. The WAF log group is in us-east-1 (WAFv2 CloudFront scope requirement); the project CMK is eu-* regional — encrypting it would require a separate us-east-1 CMK with its own lifecycle, which is disproportionate for WAF access logs. |
| **Encryption at rest** | All three DynamoDB tables use a customer-managed KMS CMK (`kms.tf`). Lambda environment variables are encrypted with the same CMK. Secrets Manager HMAC salt secret uses the CMK. Both S3 buckets use SSE-S3 (AES-256). |
| **Key management** | Annual CMK key rotation is enabled. Key usage is auditable via CloudTrail. Key revocation constitutes cryptographic erasure. |
| **IAM least privilege** | The Lambda execution role has 7 separate inline policies, each scoped to exact resource ARNs: CloudWatch Logs (its own log group only), DynamoDB per-table, Secrets Manager (exact secret ARN), KMS (exact CMK ARN), X-Ray. No `*` resource ARNs on any policy. |
| **Perimeter security** | AWS WAFv2 WebACL on CloudFront with three AWS Managed Rule Groups: `AWSManagedRulesCommonRuleSet` (OWASP Top 10), `AWSManagedRulesKnownBadInputsRuleSet` (Log4j, SSRF, Spring4Shell), `AWSManagedRulesAmazonIpReputationList`. WAF logs ship to a dedicated CloudWatch log group. |
| **API throttling** | API Gateway default route settings: 50-request burst limit, 20 rps sustained. Lambda `reserved_concurrent_executions` is defined in `variables.tf` but **commented out in dev** — the account concurrency quota is too low to reserve executions while maintaining the mandatory 10-unit unreserved pool. Re-enable before production after requesting a quota increase (see `lambda.tf` for the checklist). |
| **Supply chain** | Lambda code signing is configured via AWS Signer (`AWSLambda-SHA384-ECDSA`). Unsigned deployments are flagged; set `untrusted_artifact_on_deployment = "Enforce"` once CI/CD signs artifacts. |
| **Distributed tracing** | Lambda X-Ray Active tracing is enabled for end-to-end request visibility. |
| **TLS enforcement** | CloudFront enforces HTTPS (`redirect-to-https`). The S3 bucket policy denies all non-TLS requests. HSTS is injected via the CloudFront Response Headers Policy (max-age 1 year, includeSubDomains, preload). Production deployments should supply `var.acm_certificate_arn` to enable `TLSv1.2_2021` minimum protocol version. |
| **Security response headers** | CloudFront Response Headers Policy injects: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`. |
| **No hard-coded secrets** | Zero credentials, tokens, or secret values appear in code, environment variables, or Terraform state outputs. The HMAC salt name (not value) is passed to Lambda; the value is fetched at cold-start from Secrets Manager. |

### GDPR Controls

| Article / Principle | Implementation |
|---|---|
| **Art. 4(5) — Pseudonymisation** | Raw IP addresses are never stored. Voter identity is stored only as `HMAC-SHA256(rawIP + PollID, salt)` where `salt` is fetched from Secrets Manager. The resulting `VoterHash` is the sole voter identifier. |
| **Art. 5(1)(e) — Storage limitation** | `VoterLog` items carry a DynamoDB TTL (`ExpiresAt`) of 24 hours (configurable via `var.voter_dedup_ttl_hours`). DynamoDB auto-purges expired items. |
| **Art. 17 — Right to erasure** | Deleting a `VoterHash` item from `VoterLog` constitutes complete erasure for that voter fingerprint — no other table references the hash. CMK key revocation constitutes cryptographic erasure of all CMK-protected data. |
| **Art. 25 — Data minimisation** | No raw PII is collected. Application logs use the first 8 characters of `VoterHash` for readability. IP addresses are never written to CloudWatch, DynamoDB, or any log. |
| **Art. 32 — Security of processing** | All data at rest is encrypted (CMK for DynamoDB, Secrets Manager, Lambda env vars; AES-256 for S3). All data in transit uses TLS. WAF provides perimeter protection at the CloudFront edge. |
| **Data residency** | `var.aws_region` is validated to accept only `eu-*` regions. CloudFront is configured with `PriceClass_100` (US + EU edge locations) — a hint that limits edge processing to US and EU nodes while keeping all data storage in the configured EU region. |
| **GDPR region validation** | Terraform `variables.tf` enforces that `aws_region` must match `^eu-` — deployments to non-EU regions are blocked at plan time. |

---

## Security Guardrails & CI Checks

Every pull request targeting `main` must pass the **Security Gate** workflow (`.github/workflows/security-gate.yml`) before merge. The pipeline runs four independent jobs in parallel:

### 1. SAST — gosec

- **Tool:** [`securego/gosec`](https://github.com/securego/gosec) v2.21.4
- **Config:** `.gosec.json` at the repo root (extended G101 pattern for HMAC secrets)
- **Scope:** All Go source files under `lambda/`
- **Threshold:** Fails on findings that are simultaneously **HIGH severity** (`-severity high`) **and HIGH confidence** (`-confidence high`) — the intersection eliminates the majority of false positives that would otherwise block merges on legitimate Go patterns
- **Excluded rules:** `G104` (unhandled errors — endemic in AWS SDK usage), `G107` (URL-from-variable — false positives with runtime endpoint construction), `G304`/`G306` (filesystem taint/permissions — Lambda has no filesystem writes), `G108` (pprof endpoint — Lambda has no HTTP server), `G115` (integer overflow — extremely noisy in Go 1.22+ with valid int/uint conversions)
- **Output:** SARIF uploaded to GitHub Security tab for inline annotation
- **Guard:** If Lambda source does not yet exist (`go.mod` absent), an empty SARIF is emitted and the step passes — the scan activates automatically once Go code is committed

### 2. SCA — govulncheck

- **Tool:** [`golang.org/x/vuln/govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) v1.1.3
- **Scope:** All Go modules under `lambda/`
- **Threshold:** Fails on **HIGH** (CVSS ≥ 7.0) or **CRITICAL** (CVSS ≥ 9.0) vulnerabilities — severity is evaluated from the Go vulnerability database (`database_specific.severity`) with CVSS v3 fallback
- **Output:** Findings printed as `::error::` annotations in the Actions log

### 3. IaC — checkov

- **Tool:** [`bridgecrewio/checkov`](https://www.checkov.io/) v3.2.351
- **Config:** `.checkov.yaml` at the repo root — **allowlist approach**: only the 14 check IDs listed in that file are evaluated; every other Checkov rule is silently skipped
- **Scope:** All Terraform files under `terraform/`
- **Pre-flight:** `terraform fmt -check -recursive` and `terraform validate` must pass before checkov runs
- **Threshold:** Allowlist contains only HIGH/CRITICAL SOC2/GDPR controls; `--soft-fail-on LOW,MEDIUM,INFO` is a belt-and-suspenders guard in case a lower-severity check is ever added to the YAML
- **Output:** SARIF uploaded to GitHub Security tab; CLI summary in the Actions log
- **Documented suppressions:** All `checkov:skip` annotations in the Terraform files include a justification comment explaining why the control does not apply (design decision, circular dependency, AWS constraint, or GDPR conflict); these are only relevant to the Acceptance stage which runs all checks

### 4. Secrets — TruffleHog

- **Tool:** [`trufflesecurity/trufflehog`](https://github.com/trufflesecurity/trufflehog) v3.88.1
- **Scope:** All commits introduced by the PR (`base → head` range)
- **Mode:** `--only-verified` — only reports secrets that can be confirmed against their respective service APIs, reducing false positives
- **Threshold:** Any verified secret found fails the build immediately

### Pre-Merge Scanner Tuning

The three scanners are tuned for **zero-noise, high-signal** operation. The philosophy is: a scanner that produces false-positive noise will be bypassed — by engineers adding blanket suppressions, by CI being ignored, or by the gate being removed entirely. A focused gate that only fires on genuine catastrophic-risk findings earns trust and stays in place.

#### Two-stage strategy

| Stage | Trigger | Behavior | Scanners |
|---|---|---|---|
| **Pre-Merge** | Every PR targeting `main` | **Blocking** — PR cannot merge until all jobs pass | gosec, govulncheck, checkov (allowlist), TruffleHog |
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
- Cross-region replication (`CKV_AWS_144`) — conflicts with GDPR EU-only data-residency; skip annotations in `.tf` files document this
- SSE-KMS for S3 (`CKV_AWS_145`) — circular Terraform dependency with CloudFront OAC; SSE-S3 (AES-256) is GDPR-compliant; skip annotations document this
- S3 versioning on log bucket (`CKV_AWS_21`) — append-only audit log; versioning creates unbounded storage without recovery benefit
- CloudFront geo-restriction (`CKV_AWS_374`) — `PriceClass_100` is the chosen data-residency control
- CloudFront origin failover (`CKV_AWS_310`) — second S3 bucket in different region would violate GDPR EU-only constraint
- API Gateway route authorisation (`CKV_AWS_309`) — intentionally public polling endpoint; input validation and dedup are Lambda-enforced
- Lambda VPC placement (`CKV_AWS_117`) — disproportionate for this architecture; all service access is via AWS service endpoints

---

#### gosec — Go SAST scanner (`.gosec.json` + CLI flags)

**Approach:** severity × confidence filter — only findings that score **HIGH** on both axes enter the gate. This is more restrictive than filtering by severity alone because many HIGH-severity gosec rules have LOW confidence in Lambda/AWS SDK contexts (meaning gosec detected a pattern but cannot determine it is exploitable in this code path).

**Active rules** (everything not in the exclude list with severity=high + confidence=high):

| Rule | What it catches | Why it belongs in pre-merge |
|---|---|---|
| `G101` | Hardcoded credentials / HMAC secrets | Any inlined secret = immediate account or GDPR breach |
| `G103` | `unsafe` package usage | Memory safety violations; potential for arbitrary memory read/write |
| `G106` | SSH `InsecureIgnoreHostKey` | Disables host verification; trivial MITM attack |
| `G204` | Command injection via `exec.Command` | Arbitrary OS command execution |
| `G402` | TLS `InsecureSkipVerify = true` | Disables certificate validation; trivial MITM on all outbound calls |
| `G403` | RSA key size < 2048 bits | Factored by modern hardware; key compromise |
| `G501–G505` | Import of `crypto/md5`, DES, RC4, SHA-1 | Cryptographically broken; data integrity and confidentiality failure |

**Excluded rules** (too noisy or structurally inapplicable for Lambda):

| Rule | Why excluded |
|---|---|
| `G104` | Unhandled errors — AWS SDK usage legitimately ignores many return values (e.g., log write failures must not crash the handler); this is the single highest-volume false-positive rule in Go codebases |
| `G107` | URL-from-variable to HTTP request — false positives when constructing AWS service endpoint URLs at runtime from environment variables |
| `G304` | File path as taint input — Lambda has no dynamic filesystem reads; all persistence goes through DynamoDB and Secrets Manager |
| `G306` | Poor file permissions on write — Lambda writes nothing to the filesystem |
| `G108` | pprof endpoint publicly accessible — Lambda has no HTTP server; `/debug/pprof` routes cannot be registered |
| `G115` | Integer overflow on type conversion — extremely noisy in Go 1.22+ for normal `int`→`int64` conversions; the Go compiler already catches genuine overflow at compile time |

---

#### govulncheck — Go dependency vulnerability scanner

**Approach:** no additional tuning needed. govulncheck already applies **call-graph reachability analysis** by default — it only reports a CVE if a vulnerable function is actually called, directly or transitively, from this codebase's code paths. This is the primary noise filter; the majority of CVEs in transitive dependencies are never reachable and are therefore never reported.

The workflow then applies a **severity filter** as a second layer: the JSON output is parsed against the Go vulnerability database (`database_specific.severity`) with a CVSS v3 fallback, and only `HIGH` (≥ 7.0) or `CRITICAL` (≥ 9.0) findings fail the build.

**Key design decisions:**

- `govulncheck ./...` uses **package-level scanning** (the default) — reachability analysis is applied. Never use `-scan module`, which reports all vulnerabilities in all modules regardless of whether any vulnerable function is ever called.
- The severity filter is applied in the workflow Python script, not via a govulncheck flag, because govulncheck has no native severity threshold option — it delegates severity metadata to the OSV database.
- `|| true` on the govulncheck invocation ensures the JSON file is always written (govulncheck exits non-zero if it finds anything), allowing the severity-parsing step to make the final pass/fail decision rather than having an unfiltered exit code gate the build.

---

### Pre-commit checklist (manual)

Before committing any change, verify:

- [ ] No raw IP address logged or stored anywhere
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
| `main.tf` | AWS provider (EU region), `aws.us_east_1` alias (WAF only), default tags |
| `variables.tf` | All input variables with validation rules and defaults |
| `outputs.tf` | CloudFront URL, API URL, bucket name, table names, function name |
| `kms.tf` | Customer-managed CMK + alias + key policy |
| `dynamodb.tf` | `PollResults`, `VoterLog` (TTL + PITR), `AuditLog` (PITR, append-only) |
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
- **GDPR region validation** in `variables.tf` — only `eu-*` regions are accepted at plan time
- **SOC2 log retention** — 365-day retention on all CloudWatch log groups; S3 audit logs transition to Glacier after 90 days, expire at the retention boundary, and incomplete multipart uploads are aborted after 7 days

---

## Build Status

| Component | Status |
|---|---|
| Terraform infrastructure | Complete — all `.tf` files written; not yet applied to a live environment |
| Go Lambda backend | Not started — directory structure and layer boundaries defined in `CLAUDE.md` |
| Frontend (HTML/JS) | Not started — Chart.js integration specified in `CLAUDE.md` |
| Security gate CI | Passing — gosec/govulncheck guard on missing source; checkov 0 hard-fail findings |
