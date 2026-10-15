from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from pkisage.ai.providers import default_decision_model
from pkisage.ai.redact import redact
from pkisage.checks.parse import load_any
from pkisage.checks.preflight import evaluate, load_profile
from pkisage.core.explain import explain, unknown_entry
from pkisage.logs.parser import PATTERNS, LogMatch
from pkisage.models import Decision, ErrorEntry, Finding

app = FastAPI(title="pkisage", version="0.1.0")


class PreflightIn(BaseModel):
    pem: str
    profile: str = "corp-web.yaml"


class ExplainIn(BaseModel):
    error: str
    ca: str | None = None


class TextIn(BaseModel):
    text: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/preflight")
def preflight(body: PreflightIn) -> list[Finding]:
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "in.pem"
        f.write_text(body.pem)
        try:
            return evaluate(load_any(f), load_profile(body.profile))
        except (ValueError, OSError) as e:
            raise HTTPException(status_code=422, detail=str(e)) from e


@app.post("/explain")
def explain_api(body: ExplainIn) -> list[ErrorEntry]:
    try:
        return explain(body.error, body.ca) or [unknown_entry()]
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.post("/triage")
def triage(body: TextIn) -> Decision:
    return default_decision_model().classify(redact(body.text))


@app.post("/log")
def log(body: TextIn) -> list[LogMatch]:
    import re

    out: list[LogMatch] = []
    for no, line in enumerate(body.text.splitlines(), 1):
        for p in PATTERNS:
            if re.search(p[1], line):
                out.append(LogMatch(pattern_id=p[0], source=p[3], category=p[2], line_no=no,
                                    line=line.strip()[:300], cause=p[4], fix=p[5]))
    return out
