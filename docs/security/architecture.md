# Vote-on-It — Security Architecture

> Source of truth: `lambda/`, `frontend/`, and `terraform/` as committed on `main`.  
> Reflects live deployment: CloudFront `E1EI37JN7MPCSC` · API GW `vpgdluhxck` · Region `eu-central-1`.

---

## Data Flow Diagram

Subgraphs represent trust boundaries. Solid arrows are request paths; dashed arrows are
response paths. All paths crossing a trust boundary are labelled with their transport
security. Steps **①–⑤** inside the Lambda node are keyed to the prose below.

```mermaid
flowchart TB

    %% ══════════════════════════════════════════════════════════════════════
    %% TRUST BOUNDARY 1 — Public Internet
    %% ══════════════════════════════════════════════════════════════════════
    subgraph PUB["Public Internet"]
        direction TB
        B["User Browser<br>─────────────────────────<br><b>① UUID Generation</b><br>crypto.randomUUID() on first load<br>Persisted in localStorage<br>Sent as voter_id in POST body<br>Raw UUID never stored server-side"]
    end

    %% ══════════════════════════════════════════════════════════════════════
    %% TRUST BOUNDARY 2 — AWS Edge  (PriceClass_100 — US + EU nodes only)
    %% ══════════════════════════════════════════════════════════════════════
    subgraph EDGE["AWS Edge — PriceClass_100 (US + EU nodes only)"]
        direction LR
        WAF["WAFv2 WebACL (us-east-1)<br>─────────────────────────<br>P10 AWSManagedRulesCommonRuleSet (OWASP Top 10)<br>P20 KnownBadInputsRuleSet (Log4j / SSRF / Spring4Shell)<br>P30 AmazonIpReputationList (botnets / scanners)<br>All rules: sampled + CloudWatch metrics"]
        CF["CloudFront Distribution E1EI37JN7MPCSC<br>─────────────────────────<br>HTTPS redirect-to-https enforce<br>HSTS max-age=31536000 · includeSubDomains · preload<br>CSP default-src self · script-src self · style-src self<br>X-Frame-Options DENY · X-Content-Type-Options nosniff<br>OAC sigv4 always-sign to S3<br>Access logs → S3 audit bucket (Glacier 90d, expire 365d)"]
    end

    %% ══════════════════════════════════════════════════════════════════════
    %% TRUST BOUNDARY 3 — AWS Cloud (eu-central-1)
    %% ══════════════════════════════════════════════════════════════════════
    subgraph CLOUD["AWS Cloud — eu-central-1 (GDPR data residency)"]
        direction TB

        S3[("S3 Frontend Bucket<br>─────────────────────────<br>index.html · config.js · app.js<br>style.css · favicon.svg<br>SSE-S3 AES-256 · Private · Versioning enabled<br>Policy: Allow CloudFront OAC ARN only<br>Policy: Deny aws:SecureTransport = false")]

        GW["API Gateway v2 HTTP API (vpgdluhxck)<br>─────────────────────────<br>POST /vote · GET /results<br>Throttle: 50 burst / 20 rps<br>CORS: CloudFront domain only — no wildcard<br>Access logs → CloudWatch (KMS encrypted · 365 days)"]

        subgraph FN["Lambda Execution Environment"]
            direction TB
            L["Go Lambda · arm64 · provided.al2023<br>──────────────────────────────────────────────────<br><b>① Input Validation</b><br>poll_id: ^poll-[a-z0-9-]{1,50}$<br>option: enum {A, B, C, D}<br>voter_id: UUID v4 lowercase regex<br>DisallowUnknownFields — reject extra keys<br>ExpressionAttributeValues — no expression injection<br>──────────────────────────────────────────────────<br><b>② HMAC-SHA256 (voter pseudonymisation)</b><br>key  = salt from Secrets Manager (cold-start read · memory-cached)<br>data = voterID + pollID<br>VoterHash = hex(HMAC-SHA256) — 64 chars<br>Raw UUID never stored · never logged · GDPR pseudonymised<br>──────────────────────────────────────────────────<br><b>③ TransactWriteItems — prevents race condition</b><br>Put  VoterLog:    ConditionExpression attribute_not_exists(VoterHash)<br>ADD  PollResults: UpdateExpression ADD #opt :one<br>Both operations commit or both roll back atomically (ACID)<br>Zero window between dedup check and counter increment<br>──────────────────────────────────────────────────<br><b>④ PutAuditLog (SOC2 — append-only)</b><br>EventID: UUID v4 · Timestamp: ISO-8601 UTC<br>ActorID: VoterHash[:8] (pseudonymised) · Action · Outcome<br>Actions: VOTE_CAST · DUPLICATE_VOTE_REJECTED · RESULTS_READ<br>──────────────────────────────────────────────────<br><b>⑤ Sanitised response envelope</b><br>500: {error: {code: INTERNAL_ERROR, message: ...}}<br>No stack traces · No internal ARNs · No raw error details<br>Panic recovery in dispatcher — deferred recover()"]
        end

        SM[("Secrets Manager<br>─────────────────────────<br>vote-on-it/dev/hmac-salt<br>value: { salt: base64(32 bytes) }<br>CMK encrypted (KMS · annual rotation)<br>Read ONCE at Lambda cold-start<br>Cached in process memory for instance lifetime<br>Never in env vars · never logged")]

        subgraph DYNAMO["DynamoDB — Encrypted at Rest (CMK · KMS) — PITR enabled on all three tables"]
            direction LR
            PR[("PollResults<br>─────────────<br>PollID (PK)<br>OptionA / B / C / D — N<br>Atomic ADD only<br>IAM: GetItem · UpdateItem<br>No overwrite possible")]
            VL[("VoterLog<br>─────────────<br>VoterHash (PK)<br>PollID (SK)<br>ExpiresAt TTL 24 h<br>GDPR: no PII stored<br>IAM: GetItem · PutItem")]
            AL[("AuditLog<br>─────────────<br>EventID (PK)<br>Timestamp (SK)<br>ActorID · Action · Outcome<br>SOC2 append-only<br>IAM: PutItem ONLY<br>UpdateItem / DeleteItem denied")]
        end

    end

    %% ══════════════════════════════════════════════════════════════════════
    %% WAF attachment to CloudFront
    %% ══════════════════════════════════════════════════════════════════════
    CF <-. "All inbound requests inspected before routing" .-> WAF

    %% ══════════════════════════════════════════════════════════════════════
    %% FLOW A — Static asset delivery (GET /)
    %% ══════════════════════════════════════════════════════════════════════
    B  -->|"TLS 1.3 — GET / (initial page load)"| CF
    CF -->|"sigv4 · OAC · HTTPS — GetObject"| S3
    S3 -.->|"HTML / JS / CSS — TLS 1.3"| CF
    CF -.->|"TLS 1.3 — HTTPS response"| B

    %% ══════════════════════════════════════════════════════════════════════
    %% FLOW B — GET /results
    %% ══════════════════════════════════════════════════════════════════════
    B  -->|"TLS 1.3 — GET /results?poll_id=poll-2026-001"| CF
    CF -->|"TLS 1.3 — forward to API origin"| GW
    GW -->|"Lambda Proxy v2.0 invoke"| L
    L  -->|"GetItem — fetch vote counts"| PR
    L  -->|"PutItem — RESULTS_READ"| AL
    L  -.->|"200 { poll_id, options: {A,B,C,D}, total }"| GW
    GW -.->|"TLS 1.3 — response"| CF
    CF -.->|"TLS 1.3 — HTTPS to browser"| B

    %% ══════════════════════════════════════════════════════════════════════
    %% FLOW C — POST /vote
    %% ══════════════════════════════════════════════════════════════════════
    B  -->|"TLS 1.3 — POST /vote { poll_id, option, voter_id=UUID }"| CF
    L  -->|"GetSecretValue (cold-start only — then memory-cached)"| SM
    L  -->|"TransactWriteItems — conditional Put attribute_not_exists"| VL
    L  -->|"TransactWriteItems — atomic ADD (same transaction as VoterLog)"| PR
    L  -->|"PutItem — VOTE_CAST or DUPLICATE_VOTE_REJECTED"| AL
    L  -.->|"200 {status: ok}   OR   409 VOTE_ALREADY_CAST"| GW
```

---

## Key Security Flow Notes

### How the UUID is pseudonymised (steps ① → ②)

The browser generates a UUID v4 (`crypto.randomUUID()` with `Math.random` fallback) on first
load and stores it in `localStorage`. This UUID is the `voter_id` in every `POST /vote`
request. On the server, Lambda immediately computes:

```
VoterHash = HMAC-SHA256( voterID + pollID,  salt )
```

where `salt` is a 32-byte random value read from AWS Secrets Manager at cold-start and held
in process memory. **The raw UUID is discarded**; only the 64-char hex hash is written to
`VoterLog`. No IP address is ever received, processed, or stored — the UUID replaces it
entirely, satisfying GDPR Article 4(5) pseudonymisation.

### How the DynamoDB transaction eliminates the race condition (step ③)

A naive two-step flow — (1) check if voter exists, (2) increment counter — has a TOCTOU race:
two concurrent requests can both pass the existence check before either writes the dedup
record, resulting in double-counting. The implementation uses a single `TransactWriteItems`
call that atomically executes both writes:

| Operation | Table | Condition |
|---|---|---|
| `Put` | `VoterLog` | `ConditionExpression: attribute_not_exists(VoterHash)` |
| `Update` | `PollResults` | `UpdateExpression: ADD #opt :one` |

DynamoDB executes these as an ACID unit. If the condition fails (voter has already voted),
the entire transaction rolls back — the counter is never incremented. There is zero window
between the dedup check and the counter write.

---

## STRIDE Threat Analysis

One primary threat per node, mapped to implemented SOC2/GDPR controls.

| Node | STRIDE | Attack Scenario | Implemented Controls |
|---|---|---|---|
| **User Browser** | **Spoofing** | Attacker steals a voter's UUID from `localStorage` (e.g., via a compromised browser extension) and replays it to cast a fraudulent vote on their behalf. | Server-side `HMAC-SHA256(voterID+pollID, salt)` with a Secrets Manager salt makes the hash unguessable without the salt. Even if the raw UUID is known, the **DynamoDB conditional Put** (`attribute_not_exists(VoterHash)`) makes replay atomically impossible — the hash was written on the first vote and the condition will permanently fail for any subsequent attempt with the same UUID+pollID pair. |
| **CloudFront + WAFv2** | **Denial of Service** | Volumetric DDoS flood or exploit burst (OWASP, Log4j, Spring4Shell) targeting the `/vote` endpoint to exhaust Lambda concurrency or DynamoDB write capacity. | WAFv2 `AmazonIpReputationList` blocks known botnet IPs at the edge before traffic reaches the origin; `AWSManagedRulesCommonRuleSet` blocks OWASP Top 10 payloads; API Gateway throttle (50 burst / 20 rps) prevents Lambda saturation; CloudFront absorbs and caches edge traffic; `reserved_concurrent_executions` (to be re-enabled for production) limits Lambda blast radius. |
| **API Gateway v2** | **Tampering** | Attacker sends a crafted JSON body containing an oversized `poll_id`, extra fields, or NoSQL-style injection strings to corrupt DynamoDB expression evaluation. | Handler calls `json.NewDecoder(...).DisallowUnknownFields()` — any extra key returns `400 INVALID_JSON`. `poll_id` is validated against `^poll-[a-z0-9-]{1,50}$`; `option` against a fixed enum; `voter_id` against a UUID v4 regex. All DynamoDB expressions use `ExpressionAttributeValues` and `ExpressionAttributeNames` — raw user input is never interpolated into expression strings. |
| **Go Lambda** | **Information Disclosure** | Unhandled exception propagates a Go stack trace containing DynamoDB table names, IAM role ARN, or internal error details to the caller, enabling reconnaissance for a follow-on attack. | Every error path returns only `{"error":{"code":"INTERNAL_ERROR","message":"An unexpected error occurred."}}`. A `defer recover()` in `dispatch()` catches panics before they reach the Lambda runtime. **Structured JSON logging** records `VoterHash[:8]` as `actor_id` — never the raw UUID, never an IP address, never internal resource identifiers. |
| **DynamoDB VoterLog + AuditLog** | **Repudiation** | A voter disputes that they voted; an insider attempts to delete AuditLog records to cover a fraudulent vote injection. | The Lambda IAM role has **`PutItem` only** on `AuditLog` — `UpdateItem` and `DeleteItem` are explicitly absent from the policy. Every vote path writes an immutable `VOTE_CAST` or `DUPLICATE_VOTE_REJECTED` record with a UUID v4 `EventID`, ISO-8601 timestamp, `VoterHash[:8]` actor, and `SUCCESS`/`FAILURE` outcome. PITR on all three tables provides point-in-time recovery against accidental or malicious table deletion. |
| **DynamoDB PollResults** | **Elevation of Privilege** | Attacker submits concurrent `POST /vote` requests with different UUIDs to artificially inflate a preferred option beyond legitimate vote counts. | `TransactWriteItems` atomically binds the dedup guard (`attribute_not_exists(VoterHash)` on `VoterLog`) and the counter increment (`ADD #opt :one` on `PollResults`) in a single ACID transaction. There is no gap between the existence check and the write — concurrent duplicates cannot both pass. Each `voter_id` hashes to a unique `VoterHash`; generating new UUIDs is rate-limited at the edge by WAF IP reputation and API Gateway throttling. |
| **Secrets Manager (HMAC salt)** | **Information Disclosure** | Attacker gains read access to the HMAC salt, enabling offline pre-computation of `VoterHash` values to enumerate which UUIDs have voted, breaking GDPR pseudonymisation. | IAM policy allows `secretsmanager:GetSecretValue` only from the Lambda execution role and only on the **exact secret ARN** (no wildcard). The secret is CMK-encrypted — accessing the raw secret store value also requires the KMS key. Lambda reads once at cold-start, caches in process memory, and **never logs, echoes, or exposes the salt value** in any response, environment variable, or CloudWatch stream. Annual CMK key rotation is enforced by Terraform. |
