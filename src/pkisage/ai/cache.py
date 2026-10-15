from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def _dir() -> Path:
    return Path(os.environ.get("PKISAGE_CACHE_DIR", Path.home() / ".cache" / "pkisage"))


def key_for(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def get(key: str) -> Any | None:
    if os.environ.get("PKISAGE_NO_CACHE"):
        return None
    f = _dir() / f"{key}.json"
    return json.loads(f.read_text()) if f.is_file() else None


def put(key: str, value: Any) -> None:
    if os.environ.get("PKISAGE_NO_CACHE"):
        return
    d = _dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{key}.json").write_text(json.dumps(value))
