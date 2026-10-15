from __future__ import annotations

import json
import ssl
import urllib.request
from typing import Any

from pkisage.netutil import open_url


class _Http:
    def __init__(self, base: str, headers: dict[str, str], insecure: bool = False,
                 timeout: float = 20.0) -> None:
        self.base, self.headers, self.timeout = base.rstrip("/"), headers, timeout
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path: str) -> Any:
        req = urllib.request.Request(
            f"{self.base}{path}", headers={"Accept": "application/json", **self.headers})
        with open_url(req, timeout=self.timeout, context=self.ctx) as r:
            return json.loads(r.read())


class DigiCertAdapter:
    """Read-only DigiCert CertCentral client (GET only)."""

    name = "digicert"

    def __init__(self, api_key: str, base: str = "https://www.digicert.com/services/v2") -> None:
        self.http = _Http(base, {"X-DC-DEVKEY": api_key})

    def get_request_status(self, request_id: str) -> dict[str, str]:
        d = self.http.get(f"/order/certificate/{request_id}")
        return {"status": str(d.get("status")),
                "common_name": str(d.get("certificate", {}).get("common_name", ""))}


class EjbcaAdapter:
    """Read-only EJBCA REST client (GET only; mutual-TLS is configured on the server side)."""

    name = "ejbca"

    def __init__(self, base: str, insecure: bool = False) -> None:
        self.http = _Http(base, {}, insecure)

    def status(self) -> dict[str, str]:
        d = self.http.get("/ejbca-rest-api/v1/ca/status")
        return {"status": str(d.get("status")), "version": str(d.get("version", ""))}

    def get_request_status(self, request_id: str) -> dict[str, str]:
        return self.status()
