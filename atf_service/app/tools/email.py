from __future__ import annotations

from typing import Dict

from app.core.audit import AUDIT
from app.core.dlp import detect_types, scan_and_redact
from app.core.policy import Policy, get_domain
from app.core.provenance import evaluate_provenance
from app.schemas import DecisionResponse, SendEmailRequest


def handle_send_email(req: SendEmailRequest, policy: Policy) -> DecisionResponse:
    # Load recent context
    recent = AUDIT.get_recent_chunks(req.session_id, limit=20)
    prov = evaluate_provenance(to_email=req.to, body=req.body, recent_chunks=recent)

    domain = get_domain(req.to)

    signals: Dict = {
        "to_domain": domain,
        "untrusted_chunk_ids": prov.untrusted_chunk_ids,
        "to_tainted_by_untrusted": prov.to_tainted_by_untrusted,
        "body_overlap_ratio_with_untrusted": prov.body_overlap_ratio_with_untrusted,
    }

    # Destination policy
    if domain in policy.email_blocked_domains():
        reason = f"BLOCK: recipient domain '{domain}' is blocked"
        AUDIT.log_decision({
            "type": "send_email",
            "session_id": req.session_id,
            "decision": "BLOCK",
            "reason": reason,
            "signals": signals,
            "to": req.to,
        })
        return DecisionResponse(decision="BLOCK", reason=reason, signals=signals)

    allowed = policy.email_allowed_domains()
    if allowed and domain not in allowed:
        reason = f"BLOCK: recipient domain '{domain}' is not in allowlist"
        AUDIT.log_decision({
            "type": "send_email",
            "session_id": req.session_id,
            "decision": "BLOCK",
            "reason": reason,
            "signals": signals,
            "to": req.to,
        })
        return DecisionResponse(decision="BLOCK", reason=reason, signals=signals)

    # DLP block types
    dlp_block = detect_types(req.body, policy.dlp_block_on())
    if dlp_block:
        signals["dlp_block_findings"] = dlp_block
        reason = f"BLOCK: DLP detected high-risk data types: {sorted(dlp_block.keys())}"
        AUDIT.log_decision({
            "type": "send_email",
            "session_id": req.session_id,
            "decision": "BLOCK",
            "reason": reason,
            "signals": signals,
            "to": req.to,
        })
        return DecisionResponse(decision="BLOCK", reason=reason, signals=signals)

    # Provenance/taint enforcement
    if prov.to_tainted_by_untrusted and policy.require_confirmation_on_untrusted_provenance():
        # For MVP, treat as block (or you can downgrade to REQUIRE_CONFIRMATION)
        reason = "BLOCK: recipient address appears to come from untrusted content"
        AUDIT.log_decision({
            "type": "send_email",
            "session_id": req.session_id,
            "decision": "BLOCK",
            "reason": reason,
            "signals": signals,
            "to": req.to,
        })
        return DecisionResponse(decision="BLOCK", reason=reason, signals=signals)

    # Body overlap threshold: if agent is trying to copy a lot of untrusted content out, block
    if prov.body_overlap_ratio_with_untrusted >= policy.max_untrusted_overlap_ratio():
        reason = (
            "BLOCK: outbound body overlaps heavily with untrusted content "
            f"(ratio={prov.body_overlap_ratio_with_untrusted:.3f})"
        )
        AUDIT.log_decision({
            "type": "send_email",
            "session_id": req.session_id,
            "decision": "BLOCK",
            "reason": reason,
            "signals": signals,
            "to": req.to,
        })
        return DecisionResponse(decision="BLOCK", reason=reason, signals=signals)

    # Redaction pass
    redact_types = policy.dlp_redact_on()
    redaction = scan_and_redact(req.body, redact_types)
    if redaction.matched:
        signals["dlp_redact_findings"] = redaction.findings
        reason = f"ALLOW_WITH_REDACTION: redacted {sorted(redaction.matched)}"
        _simulate_send(to=req.to, subject=req.subject, body=redaction.redacted_text)
        AUDIT.log_decision({
            "type": "send_email",
            "session_id": req.session_id,
            "decision": "ALLOW_WITH_REDACTION",
            "reason": reason,
            "signals": signals,
            "to": req.to,
        })
        return DecisionResponse(
            decision="ALLOW_WITH_REDACTION",
            reason=reason,
            redacted_body=redaction.redacted_text,
            signals=signals,
        )

    # Allow
    reason = "ALLOW: passed destination, DLP, and provenance checks"
    _simulate_send(to=req.to, subject=req.subject, body=req.body)
    AUDIT.log_decision({
        "type": "send_email",
        "session_id": req.session_id,
        "decision": "ALLOW",
        "reason": reason,
        "signals": signals,
        "to": req.to,
    })
    return DecisionResponse(decision="ALLOW", reason=reason, signals=signals)


def _simulate_send(to: str, subject: str, body: str) -> None:
    # Do not send real emails. This is a safe demo output.
    print("\n=== SIMULATED EMAIL SEND ===")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    print("Body:")
    print(body)
    print("=== END ===\n")
