from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import TypeAdapter

from pkisage.models import ErrorCategory, ErrorEntry

ERRORS_DIR = Path(__file__).resolve().parent.parent / "errors"
_adapter = TypeAdapter(list[ErrorEntry])


def load_library(ca: str | None = None) -> list[ErrorEntry]:
    files = [ERRORS_DIR / f"{ca}.yaml"] if ca else sorted(ERRORS_DIR.glob("*.yaml"))
    entries: list[ErrorEntry] = []
    for f in files:
        if not f.exists():
            raise FileNotFoundError(f"No error library for CA '{ca}'")
        entries.extend(_adapter.validate_python(yaml.safe_load(f.read_text())))
    return entries


def explain(text: str, ca: str | None = None) -> list[ErrorEntry]:
    return [e for e in load_library(ca) if re.search(e.pattern, text)]


def unknown_entry() -> ErrorEntry:
    return ErrorEntry(
        id="unknown", pattern="", category=ErrorCategory.UNKNOWN,
        cause="No known pattern matched.", fix="Escalate to a human with the raw error attached.")
