from __future__ import annotations

from typing import List, Literal, Optional
from pydantic import BaseModel, Field

TrustZone = Literal["trusted", "untrusted"]


class IngestRequest(BaseModel):
    session_id: str = Field(..., description="Agent session identifier")
    text: str = Field(..., description="Text content the agent just consumed")
    trust_zone: TrustZone = Field(..., description="trusted or untrusted")
    source: str = Field(..., description="Where this content came from (url, file, email, etc.)")
    language: Optional[str] = Field(None, description="Optional language tag (en, hi, etc.)")


class Evidence(BaseModel):
    chunk_ids: List[str] = Field(default_factory=list, description="Chunk IDs that influenced this field")


class SendEmailRequest(BaseModel):
    session_id: str
    to: str
    subject: str = ""
    body: str
    evidence_to: Evidence = Field(default_factory=Evidence)
    evidence_body: Evidence = Field(default_factory=Evidence)


Decision = Literal[
    "ALLOW",
    "ALLOW_WITH_REDACTION",
    "REQUIRE_CONFIRMATION",
    "BLOCK",
]


class DecisionResponse(BaseModel):
    decision: Decision
    reason: str
    redacted_body: Optional[str] = None
    signals: dict = Field(default_factory=dict)
