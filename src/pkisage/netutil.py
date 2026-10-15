from __future__ import annotations

import ssl
import urllib.request
from typing import Any
from urllib.parse import urlparse


def open_url(req: urllib.request.Request, timeout: float,
             context: ssl.SSLContext | None = None) -> Any:
    """urlopen restricted to http(s); configured URLs must never reach file:// or custom schemes."""
    if urlparse(req.full_url).scheme not in ("http", "https"):
        raise ValueError(f"refusing non-http(s) URL: {req.full_url.split(':', 1)[0]}://...")
    return urllib.request.urlopen(req, timeout=timeout, context=context)  # nosec B310
