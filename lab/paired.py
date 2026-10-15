"""Paired comparison of Jev vs the rules baseline on the frozen held-out sets (exact McNemar).

Run: .venv/bin/python lab/paired.py   (needs PKISAGE_JEV_URL / PKISAGE_JEV_API_KEY; results are cached)
Writes docs/results/paired.json. This is a *re-run*; per-set numbers can differ slightly from earlier runs.
"""
from __future__ import annotations

import json
from math import comb
from pathlib import Path

from pkisage.ai.decision import RuleBasedDecisionModel
from pkisage.ai.evaluate import evaluate_model, verify_lock
from pkisage.ai.providers import JevDecisionModel
from pkisage.env import load_dotenv

SETS = ["tests/data/heldout.jsonl", "tests/data/heldout2.jsonl"]


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact p-value; b = Jev right & rules wrong, c = Jev wrong & rules right."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = 2 * sum(comb(n, i) for i in range(k + 1)) / 2**n
    return min(1.0, p)


def main() -> None:
    load_dotenv()
    jev = JevDecisionModel.from_env()
    if jev is None:
        raise SystemExit("Set PKISAGE_JEV_URL and PKISAGE_JEV_API_KEY")
    rules = RuleBasedDecisionModel()
    out: dict[str, object] = {"sets": {}}
    tot = {"both": 0, "jev_only": 0, "rules_only": 0, "neither": 0}
    for s in SETS:
        path = Path(s)
        verify_lock(path)
        rj = evaluate_model(jev, path)
        rr = evaluate_model(rules, path)
        c = {"both": 0, "jev_only": 0, "rules_only": 0, "neither": 0}
        for a, b in zip(rj.items, rr.items, strict=True):
            assert a["text"] == b["text"]
            key = ("both" if b["correct"] else "jev_only") if a["correct"] else (
                "rules_only" if b["correct"] else "neither")
            c[key] += 1
        for k in tot:
            tot[k] += c[k]
        out["sets"][s] = {  # type: ignore[index]
            "n": rj.total, "jev_correct": rj.correct, "rules_correct": rr.correct, **c,
            "mcnemar_p": round(mcnemar_exact(c["jev_only"], c["rules_only"]), 4)}
    out["pooled"] = {**tot, "n": sum(tot.values()),
                     "mcnemar_p": round(mcnemar_exact(tot["jev_only"], tot["rules_only"]), 4)}
    Path("docs/results").mkdir(parents=True, exist_ok=True)
    Path("docs/results/paired.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
