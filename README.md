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

## Decision model

ATF returns one of:
- ALLOW
- ALLOW_WITH_REDACTION
- REQUIRE_CONFIRMATION
- BLOCK

This MVP implements ALLOW, ALLOW_WITH_REDACTION, and BLOCK.

## Policy-as-code

Policy file: `policies/default_policy.yaml`

Key controls:
- allowed email domains
- blocked domains
- allowed URL hosts (optional)
- DLP configuration and thresholds

Example snippet:

```yaml
email:
  allowed_domains:
    - org.in
  blocked_domains:
    - malicious.com

dlp:
  block_on:
    - otp
    - api_key
    - jwt
  redact_on:
    - phone
    - email
```

## Provenance and taint

In the demo, content ingested from outside the org boundary is labeled `untrusted`.

When the agent proposes a tool call, it includes evidence pointers (chunk IDs) that were used to construct critical fields (recipient and body). ATF verifies provenance by:
- checking whether the recipient domain is present in any untrusted chunk
- checking whether the outbound body has substantial overlap with untrusted chunks

If tainted content is about to leave the boundary, ATF blocks or escalates.

## API

ATF runs on port 8000.

- `POST /tool/ingest` : register content the agent just read
- `POST /tool/send_email` : validate and (if allowed) execute a simulated email
- `GET /audit/logs` : JSON audit events
- `GET /ui` : simple HTML UI

## Localization hook

`data/malicious_hi.txt` provides a Hindi/Hinglish-style injection example. Extend this folder with more Indic languages and add to `scripts/replay_attacks.py`.

## Repo structure

- `atf_service/` : FastAPI firewall service
- `agent_demo/` : demo agent that triggers the attack
- `policies/` : policy YAML
- `data/` : malicious documents
- `scripts/` : attack replay harness

## Roadmap ideas (if you have more time)

- Replace naive overlap checks with robust provenance tracking (token-level attribution)
- Add REQUIRE_CONFIRMATION flow for high-risk actions
- Add HTTP request tool wrapper and enforce host/path policy
- Add role-based policies (developer vs analyst, etc.)
- Add multilingual injection pattern pack and evaluation metrics

## Security disclaimer

This is a prototype. The "tool executions" (email send) are simulated; no real emails are sent.
