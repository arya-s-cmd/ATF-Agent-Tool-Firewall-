from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Chunk:
    chunk_id: str
    session_id: str
    text: str
    trust_zone: str
    source: str
    language: Optional[str]
    created_at: float


class AuditStore:
    """In-memory store plus optional JSONL file."""

    def __init__(self, file_path: str = "/tmp/atf_audit.jsonl") -> None:
        self._events: List[Dict] = []
        self._chunks: Dict[str, List[Chunk]] = {}
        self.file_path = file_path

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

    def ingest_chunk(
        self,
        session_id: str,
        text: str,
        trust_zone: str,
        source: str,
        language: Optional[str] = None,
    ) -> str:
        cid = f"chunk_{uuid.uuid4().hex[:10]}"
        chunk = Chunk(
            chunk_id=cid,
            session_id=session_id,
            text=text,
            trust_zone=trust_zone,
            source=source,
            language=language,
            created_at=time.time(),
        )
        self._chunks.setdefault(session_id, []).append(chunk)
        self._write_event({
            "type": "ingest",
            "ts": time.time(),
            "session_id": session_id,
            "chunk_id": cid,
            "trust_zone": trust_zone,
            "source": source,
            "language": language,
            "chars": len(text),
        })
        return cid

    def get_recent_chunks(self, session_id: str, limit: int = 20) -> List[Chunk]:
        chunks = self._chunks.get(session_id, [])
        return chunks[-limit:]

    def log_decision(self, event: Dict) -> None:
        event = {"ts": time.time(), **event}
        self._write_event(event)

    def _write_event(self, event: Dict) -> None:
        self._events.append(event)
        try:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            # best-effort logging
            pass

    def get_events(self, limit: int = 200) -> List[Dict]:
        return list(self._events[-limit:])


AUDIT = AuditStore()
