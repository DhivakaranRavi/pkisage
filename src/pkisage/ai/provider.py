from __future__ import annotations

import os
from typing import Protocol

from pkisage.models import Decision

from .redact import detect_injection

HIGH = 0.85
LOW = 0.5


class Provider(Protocol):
    """Pluggable text-only LLM provider; never used for decisions."""

    def complete(self, prompt: str, json_mode: bool = False) -> str: ...


class DecisionModel(Protocol):
    def classify(self, text: str) -> Decision: ...


def trust_auto() -> bool:
    return os.environ.get("PKISAGE_TRUST_AUTO") == "1"


def route(d: Decision) -> Decision:
    """High confidence is only a suggestion unless PKISAGE_TRUST_AUTO=1 (measured auto-route
    error rate was not zero; see docs/eval.md)."""
    if d.confidence >= HIGH:
        d.route = "auto" if trust_auto() else "suggested"
    elif d.confidence >= LOW:
        d.route = "unverified"
    else:
        d.route = "human"
    return d


def guard(text: str, d: Decision) -> Decision:
    """Untrusted-input guard: suspected prompt injection is never auto-routed."""
    if detect_injection(text):
        d.route = "human"
        d.evidence_refs.append("prompt-injection-suspected")
    return d
