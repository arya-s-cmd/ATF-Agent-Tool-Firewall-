from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from app.core.audit import Chunk


@dataclass
class ProvenanceSignals:
    untrusted_chunk_ids: List[str]
    to_tainted_by_untrusted: bool
    body_overlap_ratio_with_untrusted: float


def normalize(s: str) -> str:
    return " ".join((s or "").lower().split())


def compute_body_overlap_ratio(body: str, untrusted_chunks: List[Chunk]) -> float:
    """Naive overlap ratio: how much of the body text appears in untrusted content.

    For a hackathon MVP, we do substring-based overlap. This catches common exfil patterns:
    the agent copies large parts of what it just read.
    """
    body_n = normalize(body)
    if not body_n:
        return 0.0

    # Use 6-gram shingles
    tokens = body_n.split()
    if len(tokens) < 6:
        return 0.0

    shingles = {" ".join(tokens[i:i+6]) for i in range(len(tokens) - 5)}
    if not shingles:
        return 0.0

    untrusted_text = normalize("\n".join(c.text for c in untrusted_chunks))
    hit = sum(1 for sh in shingles if sh in untrusted_text)
    return hit / max(1, len(shingles))


def evaluate_provenance(
    to_email: str,
    body: str,
    recent_chunks: List[Chunk],
) -> ProvenanceSignals:
    untrusted = [c for c in recent_chunks if c.trust_zone == "untrusted"]
    untrusted_ids = [c.chunk_id for c in untrusted]

    to_tainted = False
    to_lower = (to_email or "").lower()
    for c in untrusted:
        if to_lower and to_lower in (c.text or "").lower():
            to_tainted = True
            break

    overlap = compute_body_overlap_ratio(body=body, untrusted_chunks=untrusted)

    return ProvenanceSignals(
        untrusted_chunk_ids=untrusted_ids,
        to_tainted_by_untrusted=to_tainted,
        body_overlap_ratio_with_untrusted=overlap,
    )
