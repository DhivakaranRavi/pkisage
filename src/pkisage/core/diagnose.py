from __future__ import annotations

from pathlib import Path

from pkisage.ai.decision import RuleBasedDecisionModel
from pkisage.ai.redact import redact
from pkisage.checks.parse import load_any
from pkisage.checks.preflight import evaluate, load_profile
from pkisage.logs.parser import parse_log
from pkisage.models import DiagnosisReport, ErrorCategory, Severity


def diagnose(
    ticket: Path | None, csr: Path | None, log: Path | None, profile: str = "corp-web.yaml"
) -> DiagnosisReport:
    evidence: list[str] = []
    fixes: list[str] = []
    category = ErrorCategory.UNKNOWN
    cause = "No root cause determined"
    verified = False
    confidence = 0.0

    if csr:
        fails = [f for f in evaluate(load_any(csr), load_profile(profile))
                 if f.severity == Severity.FAIL]
        if fails:
            f = fails[0]
            category = f.category or ErrorCategory.UNKNOWN
            cause, verified, confidence = f"Preflight rule '{f.rule_id}' failed", True, 1.0
            evidence += [f"{x.rule_id}: {x.evidence}" for x in fails]
            fixes += [x.fix for x in fails]

    if log:
        matches = parse_log(log)
        for m in matches:
            evidence.append(f"{log.name}:{m.line_no}: {m.line}")
            fixes.append(m.fix)
        if matches and not verified:
            m = matches[0]
            category, cause, verified, confidence = m.category, m.cause, True, 0.9

    if ticket and not verified:
        text = redact(ticket.read_text(errors="replace"))
        d = RuleBasedDecisionModel().classify(text)
        category, confidence = d.category, d.confidence
        cause = f"Ticket text classified as {d.category.value} (route: {d.route})"
        evidence += [f"ticket pattern: {r}" for r in d.evidence_refs]

    return DiagnosisReport(
        root_cause=cause, category=category, evidence=evidence,
        fix="; ".join(dict.fromkeys(x for x in fixes if x)), confidence=confidence,
        verified=verified)
