from __future__ import annotations

from rich.console import Console
from rich.table import Table

from pkisage.models import DiagnosisReport, Finding, Severity

console = Console()
_COLORS = {Severity.PASS: "green", Severity.WARN: "yellow", Severity.FAIL: "red"}


def print_findings(findings: list[Finding], title: str = "Findings") -> None:
    t = Table(title=title)
    for c in ("Result", "Rule", "Evidence", "Fix"):
        t.add_column(c, overflow="fold")
    for f in findings:
        t.add_row(f"[{_COLORS[f.severity]}]{f.severity.value}[/]", f.rule_id, f.evidence, f.fix)
    console.print(t)


def to_jira(r: DiagnosisReport) -> str:
    ev = "\n".join(f"* {e}" for e in r.evidence) or "* none"
    return (
        f"h3. PKI diagnosis: {r.category.value}\n"
        f"*Root cause:* {r.root_cause}\n"
        f"*Confidence:* {r.confidence:.2f} | *Verified:* {'yes' if r.verified else 'NO (needs human review)'}\n"
        f"*Evidence:*\n{ev}\n"
        f"*Fix:* {{code}}{r.fix}{{code}}\n"
    )


def kb_template(r: DiagnosisReport) -> str:
    ev = "\n".join(f"- {e}" for e in r.evidence) or "- none"
    return (
        f"# {r.category.value}: {r.root_cause}\n\n## Symptoms / evidence\n{ev}\n\n"
        f"## Resolution\n{r.fix or 'TBD'}\n\n"
        f"_Draft generated from a {'verified' if r.verified else 'UNVERIFIED'} diagnosis; "
        f"review before publishing._\n"
    )
