# Threat Model — Artifacts & Context

> Read this when reviewing security findings, re-running the threat model, working on
> items flagged in the tachi output, or updating the architecture description.

---

## What Is Tachi

[tachi](https://github.com/davidmatousek/tachi) is a STRIDE-based threat modeling
pipeline for Claude Code. It dispatches specialised agents (spoofing, tampering,
repudiation, information disclosure, denial-of-service, elevation of privilege) against
an architecture description and produces structured, version-controlled output.

The tachi agents, slash commands, and skill reference files are committed to `.claude/`
— any team member with Claude Code can run the full pipeline without any additional
setup or installation.

---

## Artifact Locations

| Artifact | Path |
|---|---|
| Architecture description (tachi input / DFD source) | `docs/security/architecture.md` |
| Latest threat model run | `docs/security/2026-05-30T07-18-09/` |
| Structured findings (7 sections) | `docs/security/2026-05-30T07-18-09/threats.md` |
| SARIF 2.1.0 (GitHub Code Scanning) | `docs/security/2026-05-30T07-18-09/threats.sarif` |
| Narrative report + remediation roadmap | `docs/security/2026-05-30T07-18-09/threat-report.md` |
| Attack trees — Mermaid, one per Critical/High | `docs/security/2026-05-30T07-18-09/attack-trees/` |

Each run produces a new timestamped subfolder under `docs/security/`. Future runs
auto-detect the previous subfolder as a baseline and produce a delta summary
(new / unchanged / updated / resolved finding counts).

---

## Current Finding Summary (run: 2026-05-30)

| Severity | Count | Key findings |
|---|---|---|
| Critical | 3 | S-6, T-5, E-4 — Sybil resistance gap (same root cause, different STRIDE angles) |
| High | 8 | S-4 (CloudFront bypass), T-9 (AuditLog SOC2 gap), I-4/I-5 (GDPR logging), D-4/D-7/D-8/D-9 (DDoS vectors) |
| Medium | 18 | Infrastructure hardening, GDPR secondary risks, configuration drift |
| Low | 9 | Operational hygiene |

**Highest priority before production:** S-6, T-5, and E-4 share the same root cause —
no per-source rate limiting, no WAF Bot Control, no CAPTCHA. Any motivated attacker can
generate unlimited fresh UUIDs and determine poll outcomes. The full remediation roadmap
is in `threat-report.md`.

---

## Re-Running the Threat Model

```
/tachi.threat-model
```

Default input: `docs/security/architecture.md`. Auto-detects the previous run in
`docs/security/` as baseline and produces a delta summary. Outputs go to a new
timestamped subfolder.

### Full pipeline (run in order)

```
/tachi.threat-model              — STRIDE analysis → threats.md, threats.sarif,
                                   threat-report.md, attack-trees/
/tachi.risk-score                — Add CVSS 3.1, exploitability, scalability,
                                   reachability scores → risk-scores.md, risk-scores.sarif
/tachi.compensating-controls     — Scan codebase against findings for existing controls,
                                   calculate residual risk → compensating-controls.md
/tachi.infographic               — Generate visual risk summary (Baseball Card /
                                   System Architecture / Risk Funnel templates)
/tachi.security-report           — Assemble PDF security report from all pipeline artifacts
```

---

## Updating the Architecture Description

If you add a new component, data flow, or trust boundary, update
`docs/security/architecture.md` before re-running the threat model.

- Subgraphs in the Mermaid flowchart represent trust boundaries.
- Solid arrows are request paths; dashed arrows are response paths.
- Label all arrows that cross a trust boundary with their transport security (e.g. `TLS 1.3`).
- GitHub renders Mermaid natively — preview in the browser after editing.
