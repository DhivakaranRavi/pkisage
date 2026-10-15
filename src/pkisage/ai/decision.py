from __future__ import annotations

from pkisage.core.explain import explain
from pkisage.logs.parser import PATTERNS
from pkisage.models import Decision, ErrorCategory

from .provider import guard, route


class RuleBasedDecisionModel:
    """Offline baseline classifier; swap for a hosted model behind the Provider interface."""

    def classify(self, text: str) -> Decision:
        return guard(text, self._classify(text))

    def _classify(self, text: str) -> Decision:
        hits = explain(text)
        cats: dict[ErrorCategory, list[str]] = {}
        for h in hits:
            cats.setdefault(h.category, []).append(h.id)
        import re

        for pid, rx, cat, *_ in PATTERNS:
            if re.search(rx, text):
                cats.setdefault(cat, []).append(pid)
        if not cats:
            return route(Decision(category=ErrorCategory.UNKNOWN, confidence=0.0))
        best = max(cats, key=lambda c: len(cats[c]))
        conf = 0.9 if len(cats) == 1 else 0.6
        return route(Decision(category=best, confidence=conf, evidence_refs=cats[best]))
