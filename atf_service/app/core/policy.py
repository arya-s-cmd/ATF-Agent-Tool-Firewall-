from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import yaml


@dataclass
class Policy:
    raw: Dict[str, Any]

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(raw=data or {})

    # Email policy helpers
    def email_allowed_domains(self) -> List[str]:
        return list((self.raw.get("email") or {}).get("allowed_domains") or [])

    def email_blocked_domains(self) -> List[str]:
        return list((self.raw.get("email") or {}).get("blocked_domains") or [])

    def require_confirmation_on_untrusted_provenance(self) -> bool:
        return bool((self.raw.get("email") or {}).get("require_confirmation_on_untrusted_provenance", False))

    # HTTP policy helpers (optional)
    def http_allowed_hosts(self) -> List[str]:
        return list((self.raw.get("http") or {}).get("allowed_hosts") or [])

    def http_blocked_hosts(self) -> List[str]:
        return list((self.raw.get("http") or {}).get("blocked_hosts") or [])

    # DLP policy
    def dlp_block_on(self) -> List[str]:
        return list((self.raw.get("dlp") or {}).get("block_on") or [])

    def dlp_redact_on(self) -> List[str]:
        return list((self.raw.get("dlp") or {}).get("redact_on") or [])

    def max_untrusted_overlap_ratio(self) -> float:
        return float((self.raw.get("dlp") or {}).get("max_untrusted_overlap_ratio", 0.2))


def get_domain(email: str) -> str:
    email = (email or "").strip()
    if "@" not in email:
        return ""
    return email.split("@", 1)[1].lower().strip()
