from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class DLPResult:
    matched: List[str]
    redacted_text: str
    findings: Dict[str, int]


RE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
RE_PHONE = re.compile(r"(?:(?:\+?91)?[\s-]*)?(?:[6-9]\d{9})\b")
RE_OTP = re.compile(r"\b\d{6}\b")
RE_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
RE_API_KEY_GENERIC = re.compile(r"\b(sk-[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{10,}|AKIA[0-9A-Z]{16})\b")


PATTERNS = {
    "email": RE_EMAIL,
    "phone": RE_PHONE,
    "otp": RE_OTP,
    "jwt": RE_JWT,
    "api_key": RE_API_KEY_GENERIC,
}


def scan_and_redact(text: str, redact_types: List[str]) -> DLPResult:
    findings: Dict[str, int] = {}
    redacted = text

    for t in redact_types:
        pat = PATTERNS.get(t)
        if not pat:
            continue
        matches = pat.findall(redacted)
        if matches:
            findings[t] = findings.get(t, 0) + len(matches)
            redacted = pat.sub("[REDACTED]", redacted)

    matched = list(findings.keys())
    return DLPResult(matched=matched, redacted_text=redacted, findings=findings)


def detect_types(text: str, types: List[str]) -> Dict[str, int]:
    findings: Dict[str, int] = {}
    for t in types:
        pat = PATTERNS.get(t)
        if not pat:
            continue
        matches = pat.findall(text)
        if matches:
            findings[t] = len(matches)
    return findings
