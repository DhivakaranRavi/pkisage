from __future__ import annotations

import re
import tempfile
from pathlib import Path

from pydantic import BaseModel

from pkisage.ai.providers import default_decision_model
from pkisage.ai.redact import redact
from pkisage.core.diagnose import diagnose
from pkisage.jira import JiraClient
from pkisage.models import Decision, DiagnosisReport

CERT_EXT = {".csr", ".req", ".pem", ".crt", ".cer"}
LOG_EXT = {".log", ".txt", ".out"}


class TicketResult(BaseModel):
    key: str
    triage: Decision
    report: DiagnosisReport
    attachments_used: dict[str, str]
    label: str


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name) or "file"


def diagnose_ticket(client: JiraClient, key: str, profile: str = "corp-web.yaml") -> TicketResult:
    text, atts = client.get_issue_with_attachments(key)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        ticket = d / "ticket.txt"
        ticket.write_text(text)
        csr: Path | None = None
        log: Path | None = None
        used: dict[str, str] = {}
        for a in atts:
            name = _safe(a["filename"])
            ext = Path(name).suffix.lower()
            if ext not in CERT_EXT | LOG_EXT:
                continue
            if (ext in CERT_EXT and csr) or (ext in LOG_EXT and log):
                continue
            path = d / name
            path.write_bytes(client.download(a["url"]))
            if ext in CERT_EXT:
                csr = path
                used["csr/cert"] = name
            else:
                log = path
                used["log"] = name
        triage = default_decision_model().classify(redact(text))
        report = diagnose(ticket, csr, log, profile)
    if report.verified:
        label = f"pkisage-{report.category.value.lower()}"
    elif triage.route == "human":
        label = "pkisage-needs-human"
    else:
        label = f"pkisage-{triage.category.value.lower()}-unverified"
    return TicketResult(key=key, triage=triage, report=report, attachments_used=used, label=label)
