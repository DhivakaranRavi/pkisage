from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from pydantic import BaseModel

from pkisage.models import ErrorCategory

from .provider import HIGH, LOW, DecisionModel

BUCKETS = [(0.0, LOW), (LOW, HIGH), (HIGH, 1.0001)]


class Bucket(BaseModel):
    label: str
    n: int
    accuracy: float | None


class EvalResult(BaseModel):
    total: int
    correct: int
    accuracy: float
    ci95_low: float
    ci95_high: float
    accuracy_excluding_ambiguous: float | None
    mean_conf_correct: float
    mean_conf_wrong: float
    auto_routed: int
    auto_routed_accuracy: float
    auto_rate: float
    unverified_rate: float
    human_rate: float
    calibration: list[Bucket]
    failures: list[dict[str, str]]
    items: list[dict[str, str | float | bool]] = []


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - m) / d, (c + m) / d


def verify_lock(dataset: Path) -> None:
    lock = dataset.with_suffix(".sha256")
    if not lock.is_file():
        raise ValueError(f"{dataset.name}: no .sha256 lock file; held-out sets must be frozen")
    want = lock.read_text().split()[0]
    got = hashlib.sha256(dataset.read_bytes()).hexdigest()
    if want != got:
        raise ValueError(f"{dataset.name} changed since it was frozen (hash mismatch)")


def evaluate_model(model: DecisionModel, dataset: Path) -> EvalResult:
    """Dataset: JSONL with {"text", "label", optional "ambiguous", "source_url"}."""
    rows = [json.loads(line) for line in dataset.read_text().splitlines() if line.strip()]
    ok_conf: list[float] = []
    bad_conf: list[float] = []
    routes = {"auto": 0, "unverified": 0, "human": 0}
    auto_ok = 0
    non_amb = non_amb_ok = 0
    bucket_n = [0] * len(BUCKETS)
    bucket_ok = [0] * len(BUCKETS)
    failures: list[dict[str, str]] = []
    items: list[dict[str, str | float | bool]] = []
    for r in rows:
        d = model.classify(r["text"])
        good = d.category == ErrorCategory(r["label"])
        items.append({"text": r["text"], "label": r["label"], "pred": d.category.value,
                      "conf": round(d.confidence, 3), "correct": good})
        (ok_conf if good else bad_conf).append(d.confidence)
        band = "auto" if d.confidence >= HIGH else "unverified" if d.confidence >= LOW else "human"
        routes[band] += 1
        if band == "auto":
            auto_ok += good
        if not r.get("ambiguous"):
            non_amb += 1
            non_amb_ok += good
        for i, (lo, hi) in enumerate(BUCKETS):
            if lo <= d.confidence < hi:
                bucket_n[i] += 1
                bucket_ok[i] += good
        if not good:
            failures.append({"text": r["text"][:110], "expected": r["label"],
                             "got": d.category.value, "conf": f"{d.confidence:.2f}",
                             "route": band, "ambiguous": str(bool(r.get("ambiguous")))})

    def mean(x: list[float]) -> float:
        return sum(x) / len(x) if x else 0.0

    n = len(rows)
    lo, hi = wilson(len(ok_conf), n)
    labels = [f"[{a:.2f}, {min(b, 1.0):.2f}{']' if b > 1 else ')'}" for a, b in BUCKETS]
    return EvalResult(
        total=n, correct=len(ok_conf), accuracy=len(ok_conf) / n if n else 0.0,
        ci95_low=lo, ci95_high=hi,
        accuracy_excluding_ambiguous=(non_amb_ok / non_amb) if non_amb else None,
        mean_conf_correct=mean(ok_conf), mean_conf_wrong=mean(bad_conf),
        auto_routed=routes["auto"],
        auto_routed_accuracy=auto_ok / routes["auto"] if routes["auto"] else 0.0,
        auto_rate=routes["auto"] / n if n else 0.0,
        unverified_rate=routes["unverified"] / n if n else 0.0,
        human_rate=routes["human"] / n if n else 0.0,
        calibration=[Bucket(label=labels[i], n=bucket_n[i],
                            accuracy=bucket_ok[i] / bucket_n[i] if bucket_n[i] else None)
                     for i in range(len(BUCKETS))],
        failures=failures, items=items)
