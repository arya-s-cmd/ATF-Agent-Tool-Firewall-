from __future__ import annotations

import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.core.audit import AUDIT
from app.core.policy import Policy
from app.schemas import IngestRequest, SendEmailRequest, DecisionResponse
from app.tools.email import handle_send_email

APP_POLICY_PATH = os.environ.get("ATF_POLICY_PATH", "/app/app/../policies/default_policy.yaml")

app = FastAPI(title="ProvenanceGuard ATF", version="0.1.0")

policy = Policy.load(APP_POLICY_PATH)

# Serve UI
UI_DIR = os.path.join(os.path.dirname(__file__), "ui")
app.mount("/static", StaticFiles(directory=UI_DIR), name="static")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/tool/ingest")
def ingest(req: IngestRequest) -> dict:
    """Register content the agent just read.

    The firewall stores recent chunks per session_id. This supports provenance/taint checks.
    """
    chunk_id = AUDIT.ingest_chunk(
        session_id=req.session_id,
        text=req.text,
        trust_zone=req.trust_zone,
        source=req.source,
        language=req.language,
    )
    return {"chunk_id": chunk_id}


@app.post("/tool/send_email", response_model=DecisionResponse)
def send_email(req: SendEmailRequest) -> DecisionResponse:
    decision = handle_send_email(req=req, policy=policy)
    return decision


@app.get("/audit/logs")
def audit_logs(limit: int = 200) -> dict:
    return {"events": AUDIT.get_events(limit=limit)}


@app.get("/ui", response_class=HTMLResponse)
def ui() -> HTMLResponse:
    index_path = os.path.join(UI_DIR, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(content=html)
