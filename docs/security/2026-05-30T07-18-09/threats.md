---
schema_version: "1.4"
date: "2026-05-30"
input_format: "mermaid"
classification: "confidential"
run_id: "2026-05-30T07-18-09"
baseline:
  source: null
  date: null
  finding_count: null
  run_id: null
coverage_gate:
  status: "pass"
  gaps:
    - { component: "AuditLog", missing_category: "info-disclosure", resolution: "findings_produced" }
---

# Threat Model — Vote-on-It

## 1. System Overview

### Components

| Component | Type | Description |
|-----------|------|-------------|
| User Browser | External Entity | End-user browser; generates UUID v4 voter_id via crypto.randomUUID() (Math.random fallback), persists in localStorage, sends POST /vote and GET /results to CloudFront |
| WAFv2 WebACL | Process | AWS WAFv2 WebACL in us-east-1 attached to CloudFront; enforces AWSManagedRulesCommonRuleSet (OWASP Top 10), KnownBadInputsRuleSet (Log4j/SSRF/Spring4Shell), AmazonIpReputationList; all rules sampled with CloudWatch metrics |
| CloudFront Distribution | Process | CDN distribution E1EI37JN7MPCSC (PriceClass_100 — US+EU); enforces HTTPS redirect-to-https, HSTS max-age=31536000, CSP default-src self, X-Frame-Options DENY, X-Content-Type-Options nosniff; OAC sigv4; access logs to S3 audit bucket |
| S3 Frontend Bucket | Data Store | Stores static frontend assets (index.html, config.js, app.js, style.css, favicon.svg); SSE-S3 AES-256, private, versioning enabled; CloudFront OAC ARN-only access policy; Deny non-TLS policy |
| API Gateway v2 HTTP API | Process | HTTP API vpgdluhxck; routes POST /vote and GET /results; throttle 50 burst/20 rps; CORS locked to CloudFront domain only; access logs KMS-encrypted, 365-day retention |
| Go Lambda | Process | Go binary arm64/provided.al2023; validates Content-Type, 512-byte body limit, poll_id regex, option enum {A,B,C,D}, voter_id UUID v4 strict; HMAC-SHA256 pseudonymisation; TransactWriteItems atomic dedup; sanitised error envelope; deferred panic recovery |
| Secrets Manager | Data Store | Stores HMAC salt (vote-on-it/dev/hmac-salt, 32-byte base64); CMK-encrypted (KMS, annual rotation); read once at Lambda cold-start; cached in process memory; never logged or exposed |
| PollResults | Data Store | DynamoDB table; PollID (PK), OptionA-D atomic counters; IAM GetItem+UpdateItem (ADD only in code); CMK-encrypted; PITR enabled |
| VoterLog | Data Store | DynamoDB table; VoterHash (PK), PollID (SK); 24h TTL (ExpiresAt); GDPR: no PII stored; IAM GetItem+PutItem; CMK-encrypted; PITR enabled |
| AuditLog | Data Store | DynamoDB table; EventID (PK), Timestamp (SK); SOC2 append-only audit trail; IAM PutItem ONLY (UpdateItem/DeleteItem denied); CMK-encrypted; PITR enabled |

### Data Flows

| Source | Destination | Data | Protocol |
|--------|-------------|------|----------|
| User Browser | CloudFront Distribution | GET / (initial page load) | TLS 1.3 HTTPS |
| CloudFront Distribution | S3 Frontend Bucket | GetObject (static assets) | sigv4 OAC HTTPS |
| S3 Frontend Bucket | CloudFront Distribution | HTML/JS/CSS response | HTTPS |
| CloudFront Distribution | User Browser | Static asset response | TLS 1.3 HTTPS |
| User Browser | CloudFront Distribution | GET /results?poll_id=... | TLS 1.3 HTTPS |
| CloudFront Distribution | API Gateway v2 HTTP API | Forward GET /results | TLS 1.3 |
| API Gateway v2 HTTP API | Go Lambda | Lambda Proxy v2.0 invoke | Internal AWS |
| Go Lambda | PollResults | GetItem (fetch vote counts) | Internal AWS SDK |
| Go Lambda | AuditLog | PutItem (RESULTS_READ event) | Internal AWS SDK |
| Go Lambda | API Gateway v2 HTTP API | 200 {poll_id, options, total} | Internal AWS |
| API Gateway v2 HTTP API | CloudFront Distribution | TLS 1.3 response | TLS 1.3 |
| CloudFront Distribution | User Browser | HTTPS response with results | TLS 1.3 HTTPS |
| User Browser | CloudFront Distribution | POST /vote {poll_id, option, voter_id} | TLS 1.3 HTTPS |
| Go Lambda | Secrets Manager | GetSecretValue (cold-start only, then memory-cached) | Internal AWS SDK |
| Go Lambda | VoterLog | TransactWriteItems conditional Put attribute_not_exists | Internal AWS SDK |
| Go Lambda | PollResults | TransactWriteItems atomic ADD (same transaction as VoterLog) | Internal AWS SDK |
| Go Lambda | AuditLog | PutItem (VOTE_CAST or DUPLICATE_VOTE_REJECTED) | Internal AWS SDK |
| Go Lambda | API Gateway v2 HTTP API | 200 {status:ok} or 409 VOTE_ALREADY_CAST | Internal AWS |
| CloudFront Distribution | WAFv2 WebACL | All inbound requests inspected before routing | Internal AWS (bidirectional) |

### Technologies

| Category | Technology | Version (if known) |
|----------|------------|--------------------|
| Cloud Provider | AWS | unknown |
| CDN | Amazon CloudFront | PriceClass_100 |
| WAF | AWS WAFv2 | unknown |
| Object Storage | Amazon S3 | unknown |
| API Layer | AWS API Gateway v2 (HTTP API) | unknown |
| Compute | AWS Lambda | Go runtime, arm64, provided.al2023 |
| Language | Go | unknown |
| Database | Amazon DynamoDB | unknown |
| Secrets Management | AWS Secrets Manager | unknown |
| Encryption | AWS KMS | unknown |
| Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options | RFC-compliant |
| Authentication (OAC) | SigV4 | AWS-standard |
| Pseudonymisation | HMAC-SHA256 | Go standard library |
| Frontend | Chart.js, localStorage | unknown |
| Infrastructure | Terraform | >= 1.6.0 |
| Region | eu-central-1 | GDPR data residency |

---

## 2. Trust Boundaries

### Trust Zones

| Zone | Trust Level | Components |
|------|-------------|------------|
| Public Internet | Untrusted | User Browser |
| AWS Edge — PriceClass_100 (US + EU nodes only) | Semi-Trusted | WAFv2 WebACL, CloudFront Distribution |
| AWS Cloud — eu-central-1 (GDPR data residency) | Trusted | S3 Frontend Bucket, API Gateway v2 HTTP API, Go Lambda, Secrets Manager, PollResults, VoterLog, AuditLog |

### Boundary Crossings

| Crossing | From Zone | To Zone | Components | Controls |
|----------|-----------|---------|------------|----------|
| Browser to Edge | Public Internet | AWS Edge | User Browser → CloudFront Distribution | TLS 1.3 HTTPS, WAFv2 inspection (OWASP rules, IP reputation, KnownBadInputs), HSTS, CSP |
| Edge to S3 Origin | AWS Edge | AWS Cloud | CloudFront Distribution → S3 Frontend Bucket | SigV4 OAC always-sign, ARN-specific bucket policy, HTTPS, SSE-S3 AES-256 |
| Edge to API Origin | AWS Edge | AWS Cloud | CloudFront Distribution → API Gateway v2 HTTP API | TLS 1.3, API Gateway throttling (50 burst/20 rps), CORS enforcement (CloudFront domain only) |

---

## 3. STRIDE Threat Findings

### 3.1 Spoofing (S)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|------------|--------|------------|------------|
| S-1 | User Browser | L7 — Agent Ecosystem | — | Voter UUID theft via localStorage extraction. An attacker who gains JavaScript execution in the victim's browser (XSS, malicious extension, compromised browser) can read the voter's UUID from localStorage and replay it to cast a vote on the victim's behalf or confirm their voting status. The stolen UUID produces the same VoterHash, enabling fraudulent identity assumption. | MEDIUM | MEDIUM | Medium | Strengthen CSP to block inline scripts and restrict script-src to known origins; implement Subresource Integrity (SRI) on all frontend assets; educate users on extension security hygiene. Consider supplementing UUID-only identity with a short-lived session token issued server-side. |
| S-2 | User Browser | L7 — Agent Ecosystem | — | Math.random UUID collision fallback. On browsers lacking crypto.randomUUID() support, the Math.random fallback is not cryptographically random, creating the possibility that two voters generate the same UUID, causing one voter to be denied voting rights under the other's identity. | LOW | LOW | Note | Replace the Math.random fallback with a cryptographically secure polyfill (e.g., crypto.getRandomValues()-based UUID generation); add browser capability detection and fail securely if no CSPRNG is available. |
| S-3 | WAFv2 WebACL | L6 — Security and Compliance | — | WAF managed rule bypass via payload encoding. An attacker with knowledge of WAF rule engine edge cases may craft requests using uncommon encoding, Unicode normalization variants, or sampling-mode gaps to evade WAF inspection, reaching the origin with malicious payloads that were not blocked. | LOW | HIGH | Medium | Enable AWS WAF full logging (not just sampled) on critical rules; subscribe to AWS Managed Rules notifications for rule updates; implement rate-based rules as a defense-in-depth layer; periodically run penetration tests targeting WAF bypass techniques specific to the deployed rule groups. |
| S-4 | CloudFront Distribution | L4 — Deployment Infrastructure | — | Direct-to-origin bypass of CloudFront security controls. If an attacker discovers the API Gateway endpoint URL (via JS source inspection, DNS enumeration, CloudFront error responses, or access log leakage), they can send requests directly to the API Gateway, bypassing WAFv2 inspection, CloudFront HSTS/CSP enforcement, and CDN-layer rate limiting. | MEDIUM | HIGH | High | Implement API Gateway resource policy restricting invocations to the specific CloudFront distribution's IP ranges or requiring a secret header set by CloudFront; alternatively, enforce mutual TLS between CloudFront and API Gateway origin; add a custom header in CloudFront that Lambda validates, rejecting requests that omit it. |
| S-5 | API Gateway v2 HTTP API | L4 — Deployment Infrastructure | — | API Gateway route exploitation via unexpected paths or methods. An attacker may attempt HTTP methods or path patterns not defined in the API routes, attempting to trigger undefined Lambda behavior, bypass input validation, or discover hidden endpoints not intended for public access. | LOW | MEDIUM | Low | Ensure all API Gateway routes explicitly return 404 for undefined paths; configure a catch-all route returning 403 to prevent enumeration of undefined paths; review Lambda dispatcher logic to ensure it returns 400/404 for unexpected routes rather than exposing error details. |
| S-6 | Go Lambda | L4 — Deployment Infrastructure | — | Sybil attack via programmatic UUID generation enabling unlimited vote identities. An attacker can generate unlimited valid UUID v4 values programmatically (trivially using standard libraries) and submit a POST /vote for each, with each UUID passing all Lambda input validation checks and producing a unique VoterHash. There is no per-IP vote limit beyond API Gateway burst throttle (50/20 rps), no captcha, no device fingerprinting, and no mechanism to detect that one source is generating many identities. This enables systematic ballot-stuffing. | HIGH | HIGH | Critical | Implement rate limiting keyed to source IP at the API Gateway or WAF level (e.g., WAF rate-based rule: max N requests per IP per 5-minute window for POST /vote); add WAF Bot Control managed rule set to detect programmatic request patterns; consider requiring a CAPTCHA for POST /vote; implement server-side per-IP vote counting with WAF custom rules; evaluate per-pollID vote caps with anomaly alerting. |

### 3.2 Tampering (T)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|------------|--------|------------|------------|
| T-1 | WAFv2 WebACL | L6 — Security and Compliance | — | WAF managed rule update regression introduces false positives or new rule gaps. AWS-pushed updates to managed rule sets may block previously-valid legitimate traffic or fail to cover newly-discovered attack patterns, with no application-team control over the update schedule. | LOW | MEDIUM | Low | Subscribe to AWS Security Bulletins and managed rule group changelogs; implement CloudWatch alarms on WAF block rate with anomaly detection to detect sudden spikes (false positive wave) or drops (rule gap); test rule updates in a staging environment before production via WAF rule overrides. |
| T-2 | CloudFront Distribution | L4 — Deployment Infrastructure | — | S3 static asset tampering via OAC policy drift. If the S3 bucket policy is modified through Terraform drift, manual console changes, or misconfigured CI/CD pipelines to allow additional IAM principals or direct public access, an attacker with write access can replace frontend assets with malicious content, enabling mass voter UUID exfiltration or vote manipulation. | LOW | HIGH | Medium | Enable AWS Config rule to detect S3 bucket policy changes from the approved Terraform baseline; implement S3 Object Lock in governance mode on production assets; enable CloudTrail for S3 data events to alert on unauthorized PutObject operations; use S3 versioning (already enabled) to detect and roll back unauthorized changes. |
| T-3 | S3 Frontend Bucket | Unclassified | — | Frontend asset injection via compromised CI/CD credentials. If IAM credentials used by CI/CD pipelines to deploy frontend assets are compromised (leaked secrets, compromised developer workstation, insecure CI/CD configuration), an attacker can replace or inject malicious JavaScript into the S3 bucket, serving malicious code to all users loading the frontend. | LOW | HIGH | Medium | Rotate CI/CD IAM credentials on a regular schedule; use IAM roles for CI/CD (OIDC federation from GitHub Actions or similar) instead of long-lived access keys; enable S3 MFA Delete; implement deployment pipeline approval gates; integrate S3 PutObject events into a security alerting pipeline with hash verification against build artifacts. |
| T-4 | API Gateway v2 HTTP API | L4 — Deployment Infrastructure | — | Throttle limit misconfiguration via Terraform drift silently removes burst protection. If the API Gateway throttle configuration (50 burst/20 rps) is changed through Terraform drift or manual override, rate limiting protection is silently removed, exposing Lambda and DynamoDB to unbounded request rates. | LOW | HIGH | Medium | Implement Terraform state drift detection (e.g., terraform plan in CI/CD with drift alerting); use AWS Config managed rule `API_GW_EXECUTION_LOGGING_ENABLED` and custom Config rules to validate throttle settings; set CloudWatch alarms on API Gateway 429 response count with baseline comparisons. |
| T-5 | Go Lambda | L4 — Deployment Infrastructure | — | Systematic ballot-stuffing via concurrent multi-identity vote submission. An attacker automating POST /vote with distinct UUID v4 values for each request — each producing a unique VoterHash and passing all validation — can systematically inflate vote counts for a preferred option. The TransactWriteItems atomic operation prevents duplicate votes per UUID but does not prevent distinct-UUID flooding. This differs from a DDoS: the intent is not availability disruption but controlled poll result manipulation. | HIGH | HIGH | Critical | Implement WAF rate-based rule on POST /vote endpoint keyed to source IP (e.g., max 3 requests per 5-minute window per IP); add WAF Bot Control managed rule set; evaluate CAPTCHA for POST /vote; implement server-side per-poll anomaly detection (e.g., alert when vote velocity from single IP subnet exceeds threshold); consider requiring a signed challenge token for vote submission. |
| T-6 | Secrets Manager | L6 — Security and Compliance | — | HMAC salt rotation invalidating VoterLog deduplication history. If the HMAC salt value stored in Secrets Manager is rotated (as opposed to only the KMS CMK wrapping key rotating), all existing VoterHash values computed under the old salt become mismatched with the new salt's output for the same UUIDs. Voters who voted under the old salt can vote again under the new salt because their new VoterHash is not in VoterLog, silently breaking the dedup guarantee. | LOW | HIGH | Medium | Implement an explicit salt rotation policy that never rotates the salt value itself during active polling periods; when salt rotation is required (e.g., suspected compromise), execute a migration that recomputes all VoterLog hashes under the new salt before the old salt is decommissioned; add a version field to the VoterHash to enable multi-salt lookups during rotation windows; document and enforce the rotation policy in runbooks. |
| T-7 | PollResults | L2 — Data Operations | — | DynamoDB PollResults tampering via IAM privilege misuse enabling counter overwrite. The Lambda IAM role has UpdateItem on PollResults. Although the current Lambda code uses only ADD expressions, a compromised Lambda code path (malicious dependency, injected code) could perform UpdateItem with a SET expression, setting vote counters to arbitrary values rather than incrementing them. | LOW | HIGH | Medium | Implement DynamoDB condition expressions in all UpdateItem calls to enforce the ADD-only semantic at the DynamoDB layer (not just in code logic); audit Go dependencies for supply-chain risks; implement AWS CloudTrail data event logging for PollResults to detect anomalous UpdateItem patterns; use AWS Config to monitor IAM policy changes on the Lambda role. |
| T-8 | VoterLog | L2 — Data Operations | — | VoterLog TTL manipulation enabling premature re-voting. A compromised Lambda code path could emit incorrect ExpiresAt TTL values (e.g., a very short TTL of seconds rather than 24h) causing VoterLog entries to expire prematurely and allowing voters to re-vote before the intended dedup window. | LOW | MEDIUM | Low | Add server-side validation that ExpiresAt = current_time + 86400 (24h) with a tolerance of ±60 seconds before writing to VoterLog; implement CloudWatch metric filter on the configured TTL value in Lambda logs to detect anomalous TTL values; add unit tests for the ExpiresAt computation. |
| T-9 | AuditLog | L5 — Evaluation and Observability | — | AuditLog write suppression via exception swallowing breaks SOC2 auditability. If the PutItem call to AuditLog raises an exception (DynamoDB WCU exhaustion, IAM permission error, connectivity issue) and the Lambda exception handler swallows it to maintain availability, votes are recorded in PollResults with no corresponding AuditLog entry, creating an undetectable SOC2 compliance gap. The deferred recover() in the dispatcher could mask such failures. | MEDIUM | HIGH | High | Treat AuditLog write failures as fatal — propagate the error and return 500 to the caller rather than silently continuing; implement a dead-letter queue or secondary audit store (e.g., CloudWatch Logs structured event) as a fallback for AuditLog write failures; add CloudWatch metric filter to alert on any Lambda invocation that completes a vote without a corresponding AuditLog event; test AuditLog failure mode explicitly in integration tests. |

### 3.3 Repudiation (R)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|------------|--------|------------|------------|
| R-1 | User Browser | L7 — Agent Ecosystem | — | Voter repudiates vote claiming UUID theft. A voter may dispute that they cast a vote, claiming their UUID was stolen from localStorage by a browser extension or XSS attack and used by a third party. Because the system has no cryptographic proof-of-possession for the UUID (no asymmetric signature from the browser), the system cannot definitively refute this claim. | MEDIUM | LOW | Low | Document the pseudonymisation design in user-facing privacy notices; consider issuing a server-signed challenge token that the browser must present alongside the UUID for POST /vote, creating a proof-of-interaction that is harder to steal in isolation; maintain CloudFront access logs to correlate IP-level access patterns as circumstantial evidence. |
| R-2 | WAFv2 WebACL | L6 — Security and Compliance | — | WAF sampling gaps create forensic blind spots for attack reconstruction. WAF rules are configured in sampled mode, meaning only a fraction of requests are logged. Attacks that are detected and blocked may not be fully recorded, leaving gaps in the forensic timeline during incident investigations and potentially violating SOC2 logging completeness requirements. | MEDIUM | MEDIUM | Medium | Enable full WAF logging on all rules (not just sampled) by configuring WAF Logging to an S3 bucket or Kinesis Data Firehose; implement log retention of at least 365 days aligned with SOC2 requirements; create CloudWatch dashboards for WAF block events to enable real-time monitoring; review WAF logging scope during SOC2 audits. |
| R-3 | CloudFront Distribution | L4 — Deployment Infrastructure | — | CloudFront access log asynchrony creates minor forensic gaps for cached responses. CloudFront access logs are written asynchronously to the S3 audit bucket. For edge-cached responses (cache hits), the log entry timing may be delayed or aggregated, creating minor gaps in the precise request timeline. | LOW | LOW | Note | Accept as residual risk given CloudFront's log completeness for origin-forwarded requests; supplement CloudFront logs with API Gateway access logs for all API interactions (which are not cached); ensure CloudWatch Log Insights queries join CloudFront and API Gateway logs on correlation IDs for incident investigation. |
| R-4 | API Gateway v2 HTTP API | L4 — Deployment Infrastructure | — | API Gateway access log field omission weakens non-repudiation evidence. If the API Gateway v2 access log format does not include all required fields (requestTime, routeKey, httpMethod, identity.sourceIp, requestId), the logs may not provide sufficient forensic evidence to attribute API requests to source IPs and timestamps in a compliance audit or legal proceeding. | MEDIUM | MEDIUM | Medium | Explicitly configure the API Gateway v2 access log format in Terraform to include: $context.requestTime, $context.routeKey, $context.httpMethod, $context.identity.sourceIp, $context.requestId, $context.integrationStatus, $context.status; validate the log format in CI/CD by parsing sample log entries; include the log format specification in the SOC2 evidence package. |
| R-5 | Go Lambda | L4 — Deployment Infrastructure | — | Lambda log stream fragmentation impedes transaction reconstruction. Multiple concurrent Lambda instances write to separate CloudWatch log streams. Without a consistent correlation ID (e.g., the API Gateway requestId) propagated through all log entries for a single vote transaction, forensic reconstruction across concurrent instances is difficult and time-consuming during incident response. | MEDIUM | MEDIUM | Medium | Inject the API Gateway requestId as a structured log field in every Lambda log entry; implement structured JSON logging with fields: requestId, actor_id (VoterHash[:8]), poll_id, action, outcome, timestamp; use CloudWatch Log Insights with requestId-based queries to reconstruct complete transaction timelines across log streams; test log reconstruction in staging. |

### 3.4 Information Disclosure (I)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|------------|--------|------------|------------|
| I-1 | WAFv2 WebACL | L6 — Security and Compliance | — | WAF rule evaluation timing oracle enables adaptive attack refinement. An attacker probing WAF rule boundaries may observe response time or error code differences between requests blocked at WAF versus those reaching the origin, providing an oracle for identifying which rule blocks which payload type and enabling adaptive payload construction. | LOW | LOW | Note | Accept as residual risk inherent to any WAF deployment; mitigate by ensuring error responses from CloudFront have consistent timing (use synthetic delays if needed); ensure WAF block responses and origin error responses return identical status codes (e.g., both 403) to reduce distinguishability. |
| I-2 | CloudFront Distribution | L4 — Deployment Infrastructure | — | CloudFront error response exposes backend infrastructure metadata. Default or poorly-configured CloudFront error pages may reveal the API Gateway endpoint URL in redirect headers, the S3 bucket ARN in Access Denied error bodies, or AWS region information in response headers, enabling more targeted reconnaissance against the origin. | MEDIUM | MEDIUM | Medium | Configure custom CloudFront error pages for all 4xx and 5xx status codes that return only a branded error message with no infrastructure details; ensure the API Gateway URL is not embedded in frontend JavaScript; set CloudFront to suppress AWS-default error page bodies; audit all response headers for infrastructure metadata leakage. |
| I-3 | S3 Frontend Bucket | Unclassified | — | S3 audit bucket misconfiguration exposes CloudFront access logs containing traffic pattern data. If the S3 audit bucket policy is overly permissive, CloudFront access logs (containing request URIs, edge node details, timing data, and user-agent strings) could be read by unauthorized parties, revealing voting traffic patterns even without direct PII exposure. | LOW | LOW | Note | Apply strict bucket policy on the S3 audit log bucket (deny all public access, allow only specific audit IAM roles); enable S3 Block Public Access for the audit bucket; use S3 Object Lock in Compliance mode to prevent log tampering; restrict GetObject access to named IAM principals only. |
| I-4 | API Gateway v2 HTTP API | L4 — Deployment Infrastructure | — | API Gateway access logs capture voter_id UUID in plaintext breaking GDPR pseudonymisation. If API Gateway v2 access logging is configured with request body or header logging, the voter_id UUID value appears in CloudWatch logs in plaintext. Although the Lambda pseudonymises the UUID server-side, the presence of the raw UUID in API Gateway logs (retained for 365 days) breaks the GDPR pseudonymisation guarantee — the UUID is stored alongside the IP and timestamp, enabling voter tracking. | MEDIUM | HIGH | High | Explicitly configure API Gateway v2 access log format to exclude request body content; review the $context.requestOverride and body logging settings; implement CloudWatch log group resource policy to restrict access; if body logging is needed for debugging, use sampling with immediate PII scrubbing; verify in code review that body content does not appear in API Gateway access logs. |
| I-5 | Go Lambda | L4 — Deployment Infrastructure | — | Lambda structured log over-logging by developer debug code exposes raw UUIDs or internal resource identifiers. A developer adding temporary debug log statements during troubleshooting may inadvertently log the full voter_id UUID (pre-pseudonymisation), full VoterHash, or internal DynamoDB error details containing table ARNs or IAM role information. These logs persist in CloudWatch for 365 days and are accessible to anyone with CloudWatch read access to the log group. | MEDIUM | HIGH | High | Implement a structured logging library that enforces PII field filtering (automatically redacting any field matching UUID v4 pattern or containing the string "voter"); establish a code review checklist item specifically for log statements (no raw UUIDs, no internal ARNs, no DynamoDB error details); implement log scanning in CI/CD (e.g., regex scan for UUID v4 patterns in test log output); set CloudWatch log group resource policy to restrict access to the log group. |
| I-6 | Secrets Manager | L6 — Security and Compliance | — | HMAC salt exposure via Lambda memory inspection or debug code path. The HMAC salt is cached in Lambda process memory for the instance lifetime. A vulnerability in the Go runtime, a transient memory disclosure bug, or a developer-added debug endpoint that dumps environment state could expose the in-memory salt value, enabling offline pre-computation of all VoterHash values and breaking GDPR pseudonymisation for all voters permanently. | LOW | HIGH | Medium | Never store the salt in environment variables (already compliant); implement input validation to prevent any response path from echoing back internal state; disable any debug endpoints unconditionally in production builds (use build tags); implement anomalous Secrets Manager access alerting (CloudTrail events for GetSecretValue from unexpected principals or at unexpected frequencies); plan salt rotation procedures and document the re-hashing migration path. |
| I-7 | PollResults | L2 — Data Operations | — | Real-time vote trend disclosure via continuous GET /results polling. The GET /results endpoint returns live vote counts with no time-gate. Continuous polling of this endpoint reveals real-time voter preference accumulation, enabling early trend disclosure that could influence subsequent voters (social proof or discouragement effect), undermining poll integrity even without exposing individual voter data. | HIGH | LOW | Medium | Implement result visibility gating — return cached/aggregated results only after a minimum vote threshold is reached (e.g., 10 votes) or after a poll time-gate expires; add CloudFront caching for GET /results responses with a short TTL (e.g., 30 seconds) to reduce real-time precision; implement rate limiting on GET /results at WAF level to prevent automated continuous polling. |
| I-8 | VoterLog | L2 — Data Operations | — | VoterLog hash enumeration enables voter participation status disclosure when salt is compromised. If an attacker obtains the HMAC salt (see I-6) and gains VoterLog read access (e.g., via misconfigured IAM or Lambda compromise), they can compute VoterHash for any target UUID and query VoterLog to determine whether a specific voter has participated, breaking GDPR privacy guarantees regarding voting participation status. | LOW | HIGH | Medium | Ensure VoterLog has no public or broadly-granted read access (IAM GetItem restricted to Lambda execution role only); implement salt compromise detection via CloudTrail alerting on Secrets Manager GetSecretValue from unexpected principals; in the event of salt compromise, immediately invalidate all VoterLog entries (delete the table and re-create) to prevent enumeration; document this procedure in the incident response runbook. |
| I-9 | AuditLog | L5 — Evaluation and Observability | — | AuditLog ActorID partial hash enables voter participation timeline reconstruction. AuditLog records store VoterHash[:8] as ActorID. All audit events for the same voter share the same 8-character ActorID prefix. An authorized or unauthorized reader of AuditLog with access to multiple entries can correlate entries with matching ActorID values to reconstruct a voter's complete participation timeline (vote attempts, timestamps, outcomes), representing a GDPR information disclosure risk beyond the system's stated pseudonymisation intent. | MEDIUM | MEDIUM | Medium | Evaluate replacing the ActorID field with a salted hash of VoterHash itself (a second-level hash) using a separate audit-log-specific salt, making ActorID values unlinkable to VoterHash even for AuditLog readers; restrict AuditLog read access to compliance/audit IAM roles only (current Lambda policy is PutItem-only, which is correct — ensure no read permissions exist on the table); include AuditLog access in SOC2 logical access reviews. |

### 3.5 Denial of Service (D)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|------------|--------|------------|------------|
| D-1 | WAFv2 WebACL | L6 — Security and Compliance | — | WAF rule evaluation computational overhead via complex payload crafting. An attacker could craft inputs designed to maximize WAF rule evaluation time (deeply nested structures, extremely long strings, Unicode edge cases) causing latency increases without triggering blocks, degrading throughput for legitimate users. | LOW | MEDIUM | Low | Enable WAF rate-based rules with IP-level request count limits to constrain the volume of complex evaluation attempts; configure CloudFront's minimum TTL for error responses to prevent amplification; AWS WAF internally limits evaluation complexity per request. |
| D-2 | CloudFront Distribution | L4 — Deployment Infrastructure | — | Cache poisoning denial of service via cache-differentiating header manipulation. An attacker crafting requests with unusual Accept-Encoding variants or CloudFront-recognized cache-differentiating headers could force CloudFront to cache many distinct responses for the same URL, polluting the cache and serving degraded or empty responses to subsequent users until TTL expiry. | LOW | MEDIUM | Low | Configure CloudFront cache policies to use a minimal set of allowed cache-key headers; disable forwarding of unnecessary headers to origin; implement CloudFront cache hit rate monitoring with alerts on sudden cache miss rate spikes indicating potential cache poisoning attempts. |
| D-3 | S3 Frontend Bucket | Unclassified | — | S3 request rate throttling under sustained DDoS passing edge caches. Under extreme sustained DDoS load that saturates CloudFront edge caches, origin requests to S3 could exceed per-prefix rate limits (5,500 GET/HEAD per second), causing S3 to return 503 SlowDown responses and degrading frontend delivery. | LOW | MEDIUM | Low | CloudFront's caching significantly reduces origin requests under normal load; implement S3 Transfer Acceleration for latency-sensitive environments; enable CloudFront request rate monitoring with automated response (e.g., triggering higher cache TTLs under load); S3 automatically scales for sustained traffic patterns. |
| D-4 | API Gateway v2 HTTP API | L4 — Deployment Infrastructure | — | API Gateway burst limit exhaustion via distributed requests from non-blacklisted IPs. A botnet using fresh compromised IPs not yet in the WAF AmazonIpReputationList can distribute requests across many source IPs, evading per-IP WAF rate rules while collectively exhausting the API Gateway's 50-request burst and 20 rps sustained limit, causing all legitimate voters to receive 429 responses. | MEDIUM | HIGH | High | Enable WAF Bot Control managed rule set (provides device fingerprinting beyond IP reputation); implement WAF rate-based rule with a per-IP vote-submission limit (e.g., 3 requests per 5-minute window for POST /vote); implement DDoS response team escalation runbook for API Gateway 429 surge events; consider AWS Shield Advanced for real-time DDoS response at API Gateway. |
| D-5 | Go Lambda | L4 — Deployment Infrastructure | — | Lambda cold-start storm exhausting Secrets Manager capacity during sudden traffic spike. A sudden burst of traffic triggering many simultaneous Lambda cold-starts each calling GetSecretValue could approach Secrets Manager's API rate limits, causing initialization failures or latency spikes for new Lambda instances during the warm-up period. | LOW | MEDIUM | Low | Enable Lambda provisioned concurrency for a base number of warm instances to reduce cold-start frequency under load spikes; the existing memory caching of the salt (read once per cold-start) already minimizes Secrets Manager calls; implement CloudWatch alarm on Secrets Manager ThrottleCount metric. |
| D-6 | Secrets Manager | L6 — Security and Compliance | — | Secrets Manager GetSecretValue throttling during Lambda scaling events blocks Lambda initialization. During Lambda scaling events triggered by legitimate or DDoS traffic spikes, concurrent cold-starts call GetSecretValue simultaneously. If this volume exceeds Secrets Manager's rate limit for the function's IAM role, Lambda initialization fails, halting vote processing until instances warm up. | LOW | HIGH | Medium | Configure Lambda reserved_concurrent_executions to cap maximum concurrent instances (already noted as to-be-re-enabled for production); implement Lambda provisioned concurrency to pre-warm instances; add Secrets Manager as a dependency in Lambda health checks; configure exponential backoff with jitter in the Secrets Manager GetSecretValue call with retry logic. |
| D-7 | PollResults | L2 — Data Operations | — | DynamoDB PollResults write capacity exhaustion via vote flooding. High-volume concurrent POST /vote requests (from distributed sources evading per-IP rate limits) exhaust the PollResults table's write capacity units, causing TransactWriteItems to fail with ProvisionedThroughputExceededException, preventing all vote recording. | MEDIUM | HIGH | High | Enable DynamoDB on-demand capacity mode for PollResults to auto-scale WCU without pre-provisioning; implement DynamoDB auto-scaling if using provisioned mode; configure CloudWatch alarm on ConsumedWriteCapacityUnits approaching table limits; apply WAF rate-based rules on POST /vote to reduce sustained write pressure from any single source. |
| D-8 | VoterLog | L2 — Data Operations | — | VoterLog write saturation via unique-UUID flooding consuming write capacity. An attacker generating fresh UUID v4 values floods POST /vote — each UUID passes dedup checks and results in a VoterLog PutItem within the TransactWriteItems. Sustained flooding exhausts VoterLog WCU, causing the transaction to abort and preventing all vote recording. | MEDIUM | HIGH | High | Enable DynamoDB on-demand capacity mode for VoterLog; implement WAF rate-based rules to limit POST /vote rate per source IP; consider partitioning VoterLog by poll ID to distribute write load across partitions; configure CloudWatch alarm on VoterLog ConsumedWriteCapacityUnits; implement circuit breaker in Lambda to detect and respond to sustained DynamoDB write failures. |
| D-9 | AuditLog | L5 — Evaluation and Observability | — | AuditLog write failure cascading to vote processing failure or SOC2 compliance breach. If AuditLog PutItem fails (WCU exhaustion, IAM error, connectivity) and Lambda treats it as fatal, all vote processing stops. If Lambda silently continues without the audit record, SOC2 compliance is breached. The error handling policy for AuditLog write failures is ambiguous in the current architecture, creating a critical operational risk regardless of the choice made. | MEDIUM | HIGH | High | Define an explicit error handling policy: treat AuditLog write failure as fatal (return 500 to caller, do not record the vote) to preserve SOC2 integrity over availability; implement DynamoDB on-demand capacity for AuditLog; configure a secondary audit channel (CloudWatch Logs structured event) as a fallback for AuditLog write failures during DynamoDB outages; set CloudWatch alarm on AuditLog write failure rate. |

### 3.6 Elevation of Privilege (E)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|------------|--------|------------|------------|
| E-1 | WAFv2 WebACL | L6 — Security and Compliance | — | WAF SSRF rule gap enabling Lambda metadata endpoint access. If the KnownBadInputsRuleSet SSRF patterns do not cover all current SSRF bypass techniques, an attacker could construct a payload that evades WAF and triggers Lambda to make an outbound request to internal AWS endpoints (including IMDS at 169.254.169.254), potentially retrieving temporary IAM credentials for the Lambda execution role. | LOW | HIGH | Medium | Verify Lambda execution environment does not have direct network access to the IMDS endpoint (Lambda in VPC with explicit subnet routing can isolate this); implement IMDSv2 enforcement if the Lambda operates in a VPC context; monitor KnownBadInputsRuleSet for coverage of current SSRF bypass techniques; add Lambda network egress controls to restrict outbound connections to known destinations only. |
| E-2 | CloudFront Distribution | L4 — Deployment Infrastructure | — | CloudFront OAC confused-deputy attack via second distribution. If the S3 bucket policy ARN condition check is not enforced correctly or another CloudFront distribution is inadvertently configured to use the same S3 bucket as an origin, content could be served from the protected bucket without going through the intended distribution's security controls. | LOW | MEDIUM | Low | Verify the S3 bucket policy uses aws:SourceArn condition key specifying the exact CloudFront distribution ARN; run periodic Terraform plan checks to detect bucket policy drift; use AWS Config to alert on any new S3 GetObject grants; regularly verify that the OAC condition evaluates correctly using AWS IAM Policy Simulator. |
| E-3 | API Gateway v2 HTTP API | L4 — Deployment Infrastructure | — | Unauthorized route addition via Terraform drift or developer error creates unprotected Lambda endpoints. API Gateway v2 HTTP APIs do not enforce route-level authorization by default. A new route added without corresponding Lambda authorization logic (e.g., a debug or admin route added during development) would be accessible without access control. | LOW | HIGH | Medium | Implement Terraform change approval requirements for all API Gateway route modifications (require code review + security review); add automated test asserting the exact set of expected routes and responding to unexpected ones with 403; implement Lambda authorizer as a default deny-unless-explicitly-allowed layer; use AWS Config to detect API Gateway route changes from the approved baseline. |
| E-4 | Go Lambda | L4 — Deployment Infrastructure | — | Sybil privilege elevation enabling poll outcome determination. An attacker generating unlimited UUID v4 values and submitting them at the rate permitted by WAF+API GW throttles can accumulate enough votes for a preferred option to overturn a legitimately-won outcome. Because each UUID is treated as an independent voter, the attacker effectively gains the privilege of determining the poll outcome — a capability far beyond that of a legitimate single voter. | HIGH | HIGH | Critical | Same remediation as S-6 and T-5: implement IP-keyed rate limiting at WAF level (max N POST /vote per IP per window); add WAF Bot Control for programmatic access detection; evaluate per-pollID vote velocity anomaly detection with automated rate limiting escalation; implement challenge-response (CAPTCHA) for POST /vote; add server-side Sybil detection heuristics (e.g., alert when a single IP contributes >X% of total votes for a poll). |

---

## 4. AI Threat Findings

No AI-related components were identified in the architecture input. No components matched LLM keywords (LLM, model, GPT, Claude) or AG keywords (agent, autonomous, orchestrator, MCP server, tool server, plugin).

### 4.1 Agentic Threats (AG)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | OWASP Reference | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|-----------------|------------|--------|------------|------------|

No agentic threat findings for this architecture.

### 4.2 LLM Threats (LLM)

| ID | Component | MAESTRO Layer | Agentic Pattern | Threat | OWASP Reference | Likelihood | Impact | Risk Level | Mitigation |
|----|-----------|---------------|-----------------|--------|-----------------|------------|--------|------------|------------|

No LLM threat findings for this architecture.

---

## 4a. Correlated Findings

No cross-agent correlations detected. No AI agents were dispatched; correlation rules CR-1 through CR-5 require a STRIDE+AI finding pair at the same component.

| Group | Findings | Component | Threat Summary | Risk Level |
|-------|----------|-----------|----------------|------------|

---

## 5. Coverage Matrix

| Component | S | T | R | I | D | E | AG | LLM | Total |
|-----------|---|---|---|---|---|---|----|-----|-------|
| User Browser | 2 | n/a | 1 | n/a | n/a | n/a | n/a | n/a | 3 |
| WAFv2 WebACL | 1 | 1 | 1 | 1 | 1 | 1 | n/a | n/a | 6 |
| CloudFront Distribution | 1 | 1 | 1 | 1 | 1 | 1 | n/a | n/a | 6 |
| S3 Frontend Bucket | n/a | 1 | n/a | 1 | 1 | n/a | n/a | n/a | 3 |
| API Gateway v2 HTTP API | 1 | 1 | 1 | 1 | 1 | 1 | n/a | n/a | 6 |
| Go Lambda | 1 | 1 | 1 | 1 | 1 | 1 | n/a | n/a | 6 |
| Secrets Manager | n/a | 1 | n/a | 1 | 1 | n/a | n/a | n/a | 3 |
| PollResults | n/a | 1 | n/a | 1 | 1 | n/a | n/a | n/a | 3 |
| VoterLog | n/a | 1 | n/a | 1 | 1 | n/a | n/a | n/a | 3 |
| AuditLog | n/a | 1 | n/a | 1 | 1 | n/a | n/a | n/a | 3 |
| **Total** | **6** | **9** | **5** | **9** | **9** | **4** | **0** | **0** | **42** |

### 5a. Coverage Gate Results

| Component | Determined Type | Required Categories | Evaluated Categories | Status |
|-----------|----------------|---------------------|---------------------|--------|
| User Browser | external_entity | spoofing, repudiation | spoofing, repudiation | Pass |
| WAFv2 WebACL | process | spoofing, tampering, repudiation, info-disclosure, denial-of-service, privilege-escalation | all 6 | Pass |
| CloudFront Distribution | process | spoofing, tampering, repudiation, info-disclosure, denial-of-service, privilege-escalation | all 6 | Pass |
| S3 Frontend Bucket | data_store | tampering, info-disclosure, denial-of-service | all 3 | Pass |
| API Gateway v2 HTTP API | process | spoofing, tampering, repudiation, info-disclosure, denial-of-service, privilege-escalation | all 6 | Pass |
| Go Lambda | process | spoofing, tampering, repudiation, info-disclosure, denial-of-service, privilege-escalation | all 6 | Pass |
| Secrets Manager | data_store | tampering, info-disclosure, denial-of-service | all 3 | Pass |
| PollResults | data_store | tampering, info-disclosure, denial-of-service | all 3 | Pass |
| VoterLog | data_store | tampering, info-disclosure, denial-of-service | all 3 | Pass |
| AuditLog | data_store | tampering, info-disclosure, denial-of-service | all 3 (info-disclosure gap resolved via targeted re-analysis) | Pass |

**Final Coverage Gate Status: pass** — 1 gap detected (AuditLog / info-disclosure), resolved via targeted re-analysis producing finding I-9.

---

## 6. Risk Summary

### Risk Calibration Matrix

| | LOW Likelihood | MEDIUM Likelihood | HIGH Likelihood |
|---|---|---|---|
| **HIGH Impact** | Medium | High | Critical |
| **MEDIUM Impact** | Low | Medium | High |
| **LOW Impact** | Note | Low | Medium |

### Risk by MAESTRO Layer

| MAESTRO Layer | Finding Count | Highest Severity |
|---------------|---------------|------------------|
| L4 — Deployment Infrastructure | 18 | Critical |
| L6 — Security and Compliance | 9 | Medium |
| L2 — Data Operations | 6 | High |
| L5 — Evaluation and Observability | 3 | High |
| L7 — Agent Ecosystem | 3 | Medium |
| Unclassified | 3 | Medium |

### Finding Counts by Risk Level

| Risk Level | Count | Percentage |
|------------|-------|------------|
| Critical | 3 | 7.1% |
| High | 8 | 19.0% |
| Medium | 18 | 42.9% |
| Low | 9 | 21.4% |
| Note | 4 | 9.5% |
| **Total** | **42** | **100%** |

---

## 7. Recommended Actions

| Finding ID | Component | Threat | Risk Level | Mitigation |
|------------|-----------|--------|------------|------------|
| S-6 | Go Lambda | Sybil attack via programmatic UUID generation enabling unlimited vote identities | Critical | Implement rate limiting keyed to source IP at the API Gateway or WAF level (WAF rate-based rule: max N requests per IP per 5-minute window for POST /vote); add WAF Bot Control managed rule set; consider CAPTCHA for POST /vote; implement server-side per-IP vote counting with anomaly alerting; evaluate per-pollID vote caps. |
| T-5 | Go Lambda | Systematic ballot-stuffing via concurrent multi-identity vote submission | Critical | Implement WAF rate-based rule on POST /vote keyed to source IP; add WAF Bot Control managed rule set; evaluate CAPTCHA; implement server-side per-poll anomaly detection (alert when vote velocity from single IP subnet exceeds threshold); consider requiring a signed challenge token. |
| E-4 | Go Lambda | Sybil privilege elevation enabling poll outcome determination | Critical | Implement IP-keyed rate limiting at WAF (max N POST /vote per IP per window); add WAF Bot Control; evaluate per-pollID vote velocity anomaly detection with automated rate limiting escalation; implement CAPTCHA; add server-side Sybil detection heuristics (alert when single IP contributes >X% of total votes). |
| S-4 | CloudFront Distribution | Direct-to-origin bypass of CloudFront security controls | High | Implement API Gateway resource policy restricting invocations to CloudFront IP ranges or require a secret header set by CloudFront that Lambda validates; alternatively enforce mutual TLS between CloudFront and API Gateway; reject requests missing the custom header. |
| T-9 | AuditLog | AuditLog write suppression via exception swallowing breaks SOC2 auditability | High | Treat AuditLog write failures as fatal (propagate error, return 500, do not record the vote); implement secondary audit channel (CloudWatch Logs) as fallback; add CloudWatch metric filter alerting on votes without corresponding AuditLog events; test AuditLog failure mode explicitly. |
| I-4 | API Gateway v2 HTTP API | API Gateway access logs capture voter_id UUID in plaintext breaking GDPR pseudonymisation | High | Configure API Gateway v2 access log format to exclude request body content; review body logging settings; implement CloudWatch log group resource policy; use sampling with PII scrubbing if body logging is required for debugging. |
| I-5 | Go Lambda | Lambda structured log over-logging exposes raw UUIDs or internal resource identifiers | High | Implement structured logging library enforcing PII field filtering; establish code review checklist for log statements; implement log scanning in CI/CD; restrict CloudWatch log group access. |
| D-4 | API Gateway v2 HTTP API | API Gateway burst limit exhaustion via distributed requests from non-blacklisted IPs | High | Enable WAF Bot Control; implement WAF rate-based rule per source IP for POST /vote; implement DDoS response escalation runbook; consider AWS Shield Advanced. |
| D-7 | PollResults | DynamoDB PollResults write capacity exhaustion via vote flooding | High | Enable DynamoDB on-demand capacity mode; configure CloudWatch alarm on ConsumedWriteCapacityUnits; apply WAF rate-based rules on POST /vote. |
| D-8 | VoterLog | VoterLog write saturation via unique-UUID flooding | High | Enable DynamoDB on-demand capacity mode for VoterLog; implement WAF rate-based rules; configure CloudWatch alarm on VoterLog ConsumedWriteCapacityUnits; implement Lambda circuit breaker for sustained DynamoDB write failures. |
| D-9 | AuditLog | AuditLog write failure cascading to vote processing failure or SOC2 compliance breach | High | Define explicit error handling policy (fatal on AuditLog failure); implement DynamoDB on-demand capacity; configure secondary CloudWatch Logs audit channel; set CloudWatch alarm on AuditLog write failure rate. |
| S-1 | User Browser | Voter UUID theft via localStorage extraction | Medium | Strengthen CSP; implement SRI on all frontend assets; consider supplementing UUID identity with a short-lived server-side session token; educate users on extension security hygiene. |
| S-3 | WAFv2 WebACL | WAF managed rule bypass via payload encoding | Medium | Enable full WAF logging; subscribe to AWS Managed Rules notifications; implement rate-based rules as defense-in-depth; conduct periodic WAF bypass penetration tests. |
| T-2 | CloudFront Distribution | S3 static asset tampering via OAC policy drift | Medium | Enable AWS Config rule for S3 bucket policy changes; implement S3 Object Lock in governance mode; enable CloudTrail for S3 data events; use S3 versioning for rollback detection. |
| T-3 | S3 Frontend Bucket | Frontend asset injection via compromised CI/CD credentials | Medium | Rotate CI/CD IAM credentials; use IAM roles with OIDC federation instead of long-lived keys; enable S3 MFA Delete; implement deployment pipeline approval gates; integrate S3 PutObject events into security alerting. |
| T-4 | API Gateway v2 HTTP API | Throttle limit misconfiguration via Terraform drift silently removes burst protection | Medium | Implement Terraform state drift detection in CI/CD; use AWS Config custom rules to validate throttle settings; set CloudWatch alarms on API Gateway 429 response counts. |
| T-6 | Secrets Manager | HMAC salt rotation invalidating VoterLog deduplication history | Medium | Implement explicit salt rotation policy prohibiting rotation during active polling; implement VoterLog hash migration for salt rotation events; add salt version field to VoterHash; document rotation procedures in runbooks. |
| T-7 | PollResults | DynamoDB PollResults tampering via IAM privilege misuse enabling counter overwrite | Medium | Implement DynamoDB condition expressions enforcing ADD-only semantics; audit Go dependencies for supply-chain risks; implement CloudTrail data event logging for PollResults; monitor IAM policy changes. |
| R-2 | WAFv2 WebACL | WAF sampling gaps create forensic blind spots | Medium | Enable full WAF logging; implement log retention of 365 days; create CloudWatch dashboards for WAF block events; review WAF logging scope during SOC2 audits. |
| R-4 | API Gateway v2 HTTP API | API Gateway access log field omission weakens non-repudiation evidence | Medium | Configure API Gateway v2 access log format in Terraform to include all required fields; validate log format in CI/CD; include log format specification in SOC2 evidence package. |
| R-5 | Go Lambda | Lambda log stream fragmentation impedes transaction reconstruction | Medium | Inject API Gateway requestId as structured log field in every Lambda log entry; implement structured JSON logging; use CloudWatch Log Insights for requestId-based queries; test log reconstruction in staging. |
| I-2 | CloudFront Distribution | CloudFront error response exposes backend infrastructure metadata | Medium | Configure custom CloudFront error pages returning only branded messages; suppress AWS-default error page bodies; audit all response headers for infrastructure metadata; ensure API Gateway URL is not embedded in frontend JS. |
| I-6 | Secrets Manager | HMAC salt exposure via Lambda memory inspection or debug code path | Medium | Never store salt in environment variables; implement input validation preventing response echo of internal state; disable debug endpoints in production builds; implement CloudTrail alerting on anomalous Secrets Manager GetSecretValue; document salt rotation migration path. |
| I-7 | PollResults | Real-time vote trend disclosure via continuous GET /results polling | Medium | Implement result visibility gating (minimum vote threshold or time-gate); add CloudFront caching for GET /results with short TTL; implement WAF rate limiting on GET /results to prevent automated polling. |
| I-8 | VoterLog | VoterLog hash enumeration enables voter participation status disclosure when salt is compromised | Medium | Ensure VoterLog IAM access is restricted to Lambda execution role only; implement salt compromise detection via CloudTrail alerting; document VoterLog invalidation procedure for salt compromise events. |
| I-9 | AuditLog | AuditLog ActorID partial hash enables voter participation timeline reconstruction | Medium | Evaluate replacing ActorID with a second-level hash using a separate audit-log-specific salt; restrict AuditLog read access to audit IAM roles only; include AuditLog access in SOC2 logical access reviews. |
| D-6 | Secrets Manager | Secrets Manager GetSecretValue throttling during Lambda scaling events | Medium | Configure Lambda reserved_concurrent_executions; implement Lambda provisioned concurrency; add exponential backoff with jitter in GetSecretValue calls; add Secrets Manager ThrottleCount CloudWatch alarm. |
| E-1 | WAFv2 WebACL | WAF SSRF rule gap enabling Lambda metadata endpoint access | Medium | Verify Lambda IMDS access isolation; enforce IMDSv2 if Lambda operates in VPC; monitor KnownBadInputsRuleSet coverage; add Lambda network egress controls to restrict outbound connections. |
| E-3 | API Gateway v2 HTTP API | Unauthorized route addition via Terraform drift creates unprotected Lambda endpoints | Medium | Implement Terraform change approval for API Gateway route modifications; add automated test asserting exact expected route set; implement Lambda authorizer as default deny layer; use AWS Config for route change detection. |
| S-5 | API Gateway v2 HTTP API | API Gateway route exploitation via unexpected paths or methods | Low | Ensure undefined routes return 404 explicitly; configure catch-all route returning 403; review Lambda dispatcher for unexpected route error handling. |
| T-1 | WAFv2 WebACL | WAF managed rule update regression | Low | Subscribe to AWS Security Bulletins; implement CloudWatch alarms on WAF block rate anomalies; test rule updates in staging via WAF rule overrides. |
| T-8 | VoterLog | VoterLog TTL manipulation enabling premature re-voting | Low | Add server-side ExpiresAt validation; implement CloudWatch metric filter on TTL values; add unit tests for ExpiresAt computation. |
| R-1 | User Browser | Voter repudiates vote claiming UUID theft | Low | Document pseudonymisation design in privacy notices; consider server-signed challenge token for proof-of-interaction; maintain CloudFront access logs for circumstantial evidence. |
| D-1 | WAFv2 WebACL | WAF rule computational overhead via complex payload crafting | Low | Enable WAF rate-based rules to constrain complex evaluation attempts; CloudFront absorbs burst; WAF internally limits evaluation complexity. |
| D-2 | CloudFront Distribution | Cache poisoning denial of service | Low | Configure CloudFront cache policies with minimal allowed cache-key headers; disable forwarding of unnecessary headers; monitor cache hit rate for poisoning spikes. |
| D-3 | S3 Frontend Bucket | S3 request rate throttling under sustained DDoS | Low | CloudFront caching reduces origin requests; implement S3 Transfer Acceleration; monitor CloudFront request rates; S3 auto-scales for sustained patterns. |
| D-5 | Go Lambda | Lambda cold-start storm exhausting Secrets Manager capacity | Low | Enable Lambda provisioned concurrency; existing memory caching minimizes Secrets Manager calls; implement CloudWatch alarm on Secrets Manager ThrottleCount. |
| E-2 | CloudFront Distribution | CloudFront OAC confused-deputy attack | Low | Verify S3 bucket policy uses aws:SourceArn with exact CloudFront ARN; run periodic Terraform plan checks; use AWS Config for S3 GetObject grant monitoring; verify OAC condition with IAM Policy Simulator. |
| S-2 | User Browser | Math.random UUID collision fallback | Note | Replace Math.random fallback with CSPRNG polyfill (crypto.getRandomValues()-based); add browser capability detection with secure failure mode. |
| R-3 | CloudFront Distribution | CloudFront access log asynchrony creates minor forensic gaps | Note | Accept as residual risk; supplement with API Gateway access logs for API interactions; use CloudWatch Log Insights to join logs on correlation IDs. |
| I-1 | WAFv2 WebACL | WAF rule evaluation timing oracle | Note | Accept as residual risk; ensure error responses have consistent timing; align WAF block and origin error response status codes. |
| I-3 | S3 Frontend Bucket | S3 audit bucket misconfiguration exposes CloudFront access logs | Note | Apply strict bucket policy on audit bucket; enable S3 Block Public Access; use S3 Object Lock in Compliance mode; restrict GetObject to named audit IAM principals. |
