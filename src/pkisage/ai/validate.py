from __future__ import annotations

import re

from pkisage.models import DiagnosisReport

from .provider import Provider


def validate_claims(claims: list[tuple[str, str]], source_text: str) -> list[str]:
    """Keep only claims whose cited evidence appears verbatim in the source text."""
    return [claim for claim, cite in claims if cite and cite in source_text]


_NUM = re.compile(r"\b\d+\b")
_CODE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")


def unsupported_in_reply(reply: str, facts: str) -> list[str]:
    """Numbers and `code` spans in an LLM reply that do not appear in the verified facts."""
    bad = [n for n in _NUM.findall(reply) if n not in set(_NUM.findall(facts))]
    bad += [c for c in _CODE.findall(reply) if c not in facts]
    return list(dict.fromkeys(bad))


def extract_json(text: str) -> object | None:
    import json

    m = re.search(r"\[.*\]", text, re.DOTALL)
    try:
        return json.loads(m.group(0)) if m else None
    except ValueError:
        return None


def facts_from_report(report: DiagnosisReport) -> list[str]:
    facts = [f"Root cause: {report.root_cause}", f"Category: {report.category.value}"]
    facts += [f"Evidence: {e}" for e in report.evidence]
    facts += [f"Fix step: {s.strip()}" for s in report.fix.split(";") if s.strip()]
    return facts


def cited_reply(llm: Provider, report: DiagnosisReport) -> tuple[str, list[str], bool]:
    """LLM must cite numbered facts per sentence. Sentences with missing/invalid cites are dropped.

    Returns (reply, dropped_sentences, cited_mode). Falls back to plain text (cited_mode False)
    if the model does not return the JSON structure.
    """
    facts = facts_from_report(report)
    numbered = "\n".join(f"{i}: {f}" for i, f in enumerate(facts, 1))
    prompt = (
        "Write a short polite customer reply as a JSON array of objects "
        '{"text": "<one sentence>", "cites": [<fact numbers>]}. Every sentence must cite the '
        "numbered facts it relies on. Use ONLY these facts. Do NOT claim any action was already "
        "taken; only tell the customer what to do. Output JSON only.\n"
        f"<untrusted>\n{numbered}\n</untrusted>"
    )
    raw = llm.complete(prompt)
    parsed = extract_json(raw)
    if not isinstance(parsed, list):
        return raw, [], False
    kept: list[str] = []
    dropped: list[str] = []
    for item in parsed:
        text = str(item.get("text", "")) if isinstance(item, dict) else ""
        cites = item.get("cites") if isinstance(item, dict) else None
        ok = (
            bool(text)
            and isinstance(cites, list)
            and bool(cites)
            and all(isinstance(c, int) and 1 <= c <= len(facts) for c in cites)
            and not unsupported_in_reply(text, " ".join(facts[c - 1] for c in cites))
        )
        (kept if ok else dropped).append(text)
    return " ".join(kept), dropped, True


def template_reply(report: DiagnosisReport) -> str:
    """Deterministic fallback reply built only from verified report fields (no model)."""
    lines = [f"We reviewed your request and found: {report.root_cause}."]
    lines += [f"- {e}" for e in report.evidence]
    steps = [s.strip() for s in report.fix.split(";") if s.strip()]
    if steps:
        lines.append("Please do the following:")
        lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    return "\n".join(lines)
