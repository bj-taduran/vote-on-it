# Compliance & Schema Detail

> Read this when working on Lambda Go code, DynamoDB schema, input validation, error
> handling, CORS, or anything that touches SOC2/GDPR compliance. The non-negotiable
> rules in `CLAUDE.md` still apply — this file adds the detail.

---

## DynamoDB Schema

### `PollResults` — vote counters

| Attribute | Type | Notes |
|---|---|---|
| `PollID` (PK) | S | e.g. `"poll-2026-001"` |
| `OptionA` | N | Atomic ADD only |
| `OptionB` | N | Atomic ADD only |
| `OptionC` | N | Atomic ADD only |
| `OptionD` | N | Atomic ADD only |
| `CreatedAt` | S | ISO-8601, set on first write |

IAM: `GetItem`, `Scan`, `UpdateItem`. Counter-only — no full item overwrite is possible.

### `VoterLog` — deduplication (pseudonymised, no PII)

| Attribute | Type | Notes |
|---|---|---|
| `VoterHash` (PK) | S | `HMAC-SHA256(voterID + pollID, salt)` — 64-char hex |
| `PollID` (SK) | S | Enables per-poll dedup queries |
| `ExpiresAt` | N | Unix epoch; DynamoDB TTL — 24 h (configurable via `var.voter_dedup_ttl_hours`) |

IAM: `GetItem`, `PutItem`. No raw voter identity stored — GDPR Art. 4(5) compliant.

### `AuditLog` — SOC2 immutable audit trail

| Attribute | Type | Notes |
|---|---|---|
| `EventID` (PK) | S | UUID v4 |
| `Timestamp` (SK) | S | ISO-8601 UTC |
| `ActorID` | S | `VoterHash[:8]` or `"system"` |
| `Action` | S | Enum: `VOTE_CAST`, `RESULTS_READ`, `DUPLICATE_VOTE_REJECTED` |
| `ResourceID` | S | `"PollID#poll-2026-001"` |
| `Outcome` | S | `"SUCCESS"` or `"FAILURE"` |

IAM: `PutItem` only — `UpdateItem` and `DeleteItem` are explicitly absent from the inline policy. Append-only by IAM enforcement.

---

## Input Validation (POST /vote)

All validation runs before any DynamoDB call. Order matters — size and content-type are
checked before JSON parsing begins.

| Stage | Error Code | Rule |
|---|---|---|
| Content-Type header | `INVALID_CONTENT_TYPE` | Must be `application/json` (charset suffix accepted) |
| Body size | `REQUEST_TOO_LARGE` | Max 512 bytes |
| JSON parse + unknown fields | `INVALID_JSON` | `json.NewDecoder(...).DisallowUnknownFields()` — any extra key → 400 |
| `poll_id` presence | `MISSING_POLL_ID` | Field must be present |
| `poll_id` format | `INVALID_POLL_ID` | Regex: `^poll-[a-z0-9-]{1,50}$` |
| `option` presence | `MISSING_OPTION` | Field must be present |
| `option` value | `INVALID_OPTION` | Enum: `"A"`, `"B"`, `"C"`, `"D"` |
| `voter_id` presence | `MISSING_VOTER_ID` | Field must be present |
| `voter_id` format | `INVALID_VOTER_ID` | UUID v4 strict: version nibble `4`, variant nibble `[89ab]`, lowercase |

---

## Error Response Envelope

All error responses — across all handlers and all status codes — use exactly this shape:

```json
{ "error": { "code": "ERROR_CODE", "message": "Human-readable message." } }
```

HTTP codes in use: `200`, `400`, `409`, `429`, `500`. The `500` body is always the
generic `INTERNAL_ERROR` message — no stack traces, no DynamoDB error text, no ARNs.

A `defer recover()` in the dispatcher catches unexpected panics before they reach the
Lambda runtime.

---

## HMAC Pseudonymisation Flow

```
VoterHash = hex( HMAC-SHA256( voterID + pollID,  salt ) )
```

- `salt`: 32-byte random value stored in Secrets Manager; read once at Lambda
  cold-start and cached in process memory for the instance lifetime.
- `voterID`: the UUID v4 sent by the browser — discarded immediately after hashing.
- The raw UUID is never written to DynamoDB, CloudWatch, or any response.
- GDPR Article 4(5): the hash cannot be reversed to identify any individual without
  the salt, which is isolated to Secrets Manager and protected by KMS CMK.

---

## DynamoDB Transaction (POST /vote)

A single `TransactWriteItems` call commits both operations atomically:

| Operation | Table | Key condition |
|---|---|---|
| `Put` | `VoterLog` | `ConditionExpression: attribute_not_exists(VoterHash)` |
| `Update` | `PollResults` | `UpdateExpression: ADD #opt :one` |

If the condition fails (voter has already voted), both operations roll back — the
counter is never incremented. There is zero TOCTOU gap between the dedup check and the
write. Use `ExpressionAttributeValues` and `ExpressionAttributeNames` for all
expression parameters — never interpolate user input into expression strings.

---

## CORS

- Allowed origin: exact CloudFront distribution domain (`https://<cf-domain>`).
- No wildcard `*` origins — ever.
- CORS is set at the API Gateway level in `api_gateway.tf`.

---

## GDPR Constraints (Detail)

| Article | Constraint | Implementation |
|---|---|---|
| Art. 4(5) — Pseudonymisation | No raw IP or UUID stored | HMAC-SHA256 hash only; UUID discarded post-hash |
| Art. 5(1)(e) — Storage limitation | VoterLog TTL 24 h | DynamoDB TTL auto-purges expired items |
| Art. 17 — Right to erasure | Delete VoterHash = complete erasure | No other table holds the hash; CMK revocation = cryptographic erasure of all CMK-protected data |
| Art. 25 — Data minimisation | Minimum data only | Pseudonymised hash + chosen option |
| Art. 32 — Security of processing | Encryption everywhere | CMK for DynamoDB/Secrets Manager/Lambda env; AES-256 for S3; TLS enforced at edge + S3 policy |
| Data residency | EU regions only | `variables.tf` rejects non-`eu-*` at plan time; `PriceClass_100` for edge |
| No PII in logs | CloudWatch formats omit source IP | Lambda logs use `VoterHash[:8]` only; `$context.identity.sourceIp` excluded from API GW log format |
