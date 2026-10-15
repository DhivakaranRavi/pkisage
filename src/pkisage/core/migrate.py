from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from pkisage.checks.parse import load_any
from pkisage.checks.preflight import evaluate
from pkisage.models import Finding, Profile, Severity


class AppResult(BaseModel):
    app: str
    old: list[Finding]
    new: list[Finding]

    @property
    def old_ok(self) -> bool:
        return not any(f.severity == Severity.FAIL for f in self.old)

    @property
    def new_ok(self) -> bool:
        return not any(f.severity == Severity.FAIL for f in self.new)

    @property
    def pq_vulnerable(self) -> bool:
        return any(f.rule_id == "pqc-readiness" for f in self.new)

    @property
    def verdict(self) -> str:
        if self.new_ok:
            return "OK"
        return "BREAKS" if self.old_ok else "ALREADY-FAILING"


def migrate_check(input_dir: Path, old: Profile, new: Profile) -> list[AppResult]:
    results: list[AppResult] = []
    for p in sorted(input_dir.iterdir()):
        if p.suffix.lower() not in {".csr", ".pem", ".crt", ".cer", ".req"}:
            continue
        try:
            obj = load_any(p)
        except Exception as e:
            err = [Finding(rule_id="parse", severity=Severity.FAIL, message="Unparseable",
                           evidence=str(e))]
            results.append(AppResult(app=p.stem, old=err, new=err))
            continue
        results.append(AppResult(app=p.stem, old=evaluate(obj, old), new=evaluate(obj, new)))
    return results
