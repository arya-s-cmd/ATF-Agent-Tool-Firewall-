# ProvenanceGuard ATF (Agent Tool Firewall)

ProvenanceGuard ATF is a runtime guardrail layer for tool-using AI systems (agents) that prevents prompt-injection-to-action incidents by enforcing security at the tool boundary.

This repository contains a runnable MVP:
- A FastAPI firewall service that intercepts tool calls
- A tiny demo agent that reads a malicious document and tries to exfiltrate it
- Policy-as-code (YAML) for destination rules and DLP controls
- A minimal audit log UI


## Quickstart

Requirements:
- Docker and docker-compose

Run:

```bash
cd provenanceguard-atf
docker compose up --build
```

Then, in another terminal, run the demo agent:

```bash
docker compose exec agent python demo.py --mode with_atf
```

You will see the attempted exfiltration blocked, and the safe email allowed.

To compare baseline behavior (no firewall):

```bash
docker compose exec agent python demo.py --mode no_atf
```

Open the audit log UI:
- http://localhost:8000/ui

## What this prototype demonstrates

Threat: An agent is asked to summarize a document and email a manager. The document contains hidden malicious instructions (English and Indic variants) that try to force the agent to email the full document to an attacker.

Outcome:
- Without ATF: the agent "sends" the doc to the attacker (simulated)
- With ATF: the firewall blocks the attacker email due to:
  - destination policy violation
  - DLP detection (sensitive content)
  - provenance/taint evidence (content derived from untrusted source)

## Architecture

High level:

```
+------------------+         +--------------------------+
|   Demo Agent     |         |   ProvenanceGuard ATF     |
| (simulated agent)|  HTTP   | (FastAPI middleware)      |
|------------------| ------> |--------------------------|
| reads untrusted  |         | Policy engine (YAML)      |
| content          |         | DLP (PII/secrets/OTP)     |
| proposes tool    |         | Provenance/taint checks   |
| calls            |         | Decision: allow/redact/...|
+------------------+         +--------------------------+
                                      |
                                      v
                              +------------------+
                              | Tool execution   |
                              | (simulated)      |
                              +------------------+
```

### Key design choice: do not trust model rationales

A compromised model can fabricate intent. This prototype therefore emphasizes:
- deterministic destination rules
- independent DLP scanning
- provenance/taint checks that verify whether outbound content overlaps with recently ingested untrusted content

### Decision model
ATF returns one of:
- `ALLOW`
- `ALLOW_WITH_REDACTION`
- `REQUIRE_CONFIRMATION`
- `BLOCK`

This MVP implements ALLOW, ALLOW_WITH_REDACTION, and BLOCK.

## Policy-as-code

Policy file: `policies/default_policy.yaml`

Key controls:
- allowed/blocked **email domains**
- DLP rules: block vs redact categories
- taint thresholds (how much overlap with untrusted text triggers block)

Example snippet:

```yaml
email:
  allowed_domains: ["org.in"]
  blocked_domains: ["malicious.com"]

dlp:
  block_on: ["otp", "api_key", "jwt"]
  redact_on: ["phone", "email"]

taint:
  max_untrusted_overlap_ratio: 0.20
```

## Provenance and taint

In the demo, content ingested from outside the org boundary is labeled `untrusted`.

When the agent proposes a tool call, it includes evidence pointers (chunk IDs) that were used to construct critical fields (recipient and body). ATF verifies provenance by:
- checking whether the recipient domain is present in any untrusted chunk
- checking whether the outbound body has substantial overlap with untrusted chunks

If tainted content is about to leave the boundary, ATF blocks or escalates.

## API (ATF service)

ATF runs on port 8000.

- `POST /tool/ingest` : registers content the agent just read (trust zone metadata)
- `POST /tool/send_email` : enforces destination policy, DLP, and taint checks
- `GET /audit/logs` : JSON audit events
- `GET /ui` : minimal audit UI


## Evaluation harness

Run a small attack replay to generate a quick scorecard:

```bash
docker compose exec agent python /app/scripts/replay_attacks.py
```

The harness replays multiple injection patterns (including a Hindi/Hinglish sample) and reports how many attempts were blocked vs allowed.

## Localization

The repo includes:
- `data/malicious_en.txt` (English)
- `data/malicious_hi.txt` (Hindi/Hinglish-style)

To extend localization:
1) add more samples in `data/` (e.g., `malicious_ta.txt`, `malicious_bn.txt`)
2) include them in `scripts/replay_attacks.py`
3) tune DLP patterns for local formats (phone/ID patterns)

## Productionization notes

This project is intentionally small, but it is structured for real integration:
- Keep ATF as a **sidecar service** or in-process middleware
- Replace the demo email stub with your actual email/HTTP/file tools
- Add `REQUIRE_CONFIRMATION` for high-risk actions
- Add role-based policies and per-tenant allowlists

## Limitations

This repo is a **reference implementation** focused on demonstrating enforceable guardrails.
In demo mode, “tool execution” is intentionally stubbed (no real emails are sent).
For production, swap in your actual tool adapters and keep ATF’s enforcement unchanged.
