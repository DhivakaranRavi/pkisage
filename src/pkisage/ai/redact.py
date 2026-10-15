from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)\b(pin|password|passwd|pass|secret|token|api[_-]?key)\b(\s*[=:]\s*)\S+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
]


def redact(text: str) -> str:
    text = _PATTERNS[0].sub("[REDACTED_PRIVATE_KEY]", text)
    text = _PATTERNS[1].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    text = _PATTERNS[2].sub("Bearer [REDACTED]", text)
    text = _PATTERNS[3].sub("[REDACTED_EMAIL]", text)
    return text


_INJECTION = re.compile(
    r"(?i)(ignore (all |any |the )?(previous|prior|above) (instructions|rules)"
    r"|disregard .{0,30}(instructions|rules)|you are now|system prompt|act as (an? )?"
    r"|reveal .{0,30}(prompt|key|secret|token)|</?(system|assistant)>|\bjailbreak\b)")


def detect_injection(text: str) -> bool:
    return bool(_INJECTION.search(text))
