from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pkisage.netutil import open_url


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class AcmeError(Exception):
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status, self.body = status, body
        super().__init__(f"{body.get('type', '')}: {body.get('detail', '')}")


class AcmeClient:
    """Minimal RFC 8555 client for diagnostics against a lab/test CA (not for production issuance)."""

    name = "acme"

    def __init__(self, directory_url: str, insecure: bool = False, timeout: float = 20.0) -> None:
        self.directory_url, self.timeout = directory_url, timeout
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid: str | None = None
        self.nonce: str | None = None
        self.directory: dict[str, Any] = {}

    def _raw(self, req: urllib.request.Request) -> tuple[int, dict[str, str], bytes]:
        try:
            with open_url(req, timeout=self.timeout, context=self.ctx) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def get_directory(self) -> dict[str, Any]:
        _, _, body = self._raw(urllib.request.Request(self.directory_url))
        self.directory = json.loads(body)
        return self.directory

    def _jwk(self) -> dict[str, str]:
        n = self.key.public_key().public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": b64(n.x.to_bytes(32, "big")),
                "y": b64(n.y.to_bytes(32, "big"))}

    def _post(
        self, url: str, payload: dict[str, Any] | None, _retry: int = 0
    ) -> tuple[int, dict[str, str], Any]:
        if not self.nonce:
            _, h, _ = self._raw(urllib.request.Request(
                self.directory["newNonce"], method="HEAD"))
            self.nonce = h.get("Replay-Nonce")
        header: dict[str, Any] = {"alg": "ES256", "nonce": self.nonce, "url": url}
        header.update({"kid": self.kid} if self.kid else {"jwk": self._jwk()})
        protected = b64(json.dumps(header).encode())
        pl = "" if payload is None else b64(json.dumps(payload).encode())
        der = self.key.sign(f"{protected}.{pl}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        body = json.dumps({"protected": protected, "payload": pl, "signature": sig}).encode()
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/jose+json"})
        status, headers, raw = self._raw(req)
        self.nonce = headers.get("Replay-Nonce")
        data: Any = json.loads(raw) if raw and raw.lstrip()[:1] in (b"{", b"[") else raw
        if (status == 400 and isinstance(data, dict) and data.get("type", "").endswith("badNonce")
                and _retry < 2):
            return self._post(url, payload, _retry + 1)
        if status >= 400:
            raise AcmeError(status, data if isinstance(data, dict) else {"detail": str(data)})
        return status, headers, data

    def new_account(self) -> None:
        _, h, _ = self._post(self.directory["newAccount"], {"termsOfServiceAgreed": True})
        self.kid = h.get("Location")

    def submit_csr(self, domains: list[str], csr_der: bytes) -> dict[str, Any]:
        """Run a full order. Raises AcmeError with the CA's raw problem document on rejection."""
        self.get_directory()
        self.new_account()
        _, h, order = self._post(self.directory["newOrder"], {
            "identifiers": [{"type": "dns", "value": d} for d in domains]})
        order_url = h["Location"]
        for authz_url in order["authorizations"]:
            _, _, authz = self._post(authz_url, None)
            for ch in authz["challenges"]:
                if ch["type"] == "http-01":
                    self._post(ch["url"], {})
        for _ in range(20):
            _, _, order = self._post(order_url, None)
            if order["status"] in ("ready", "valid", "invalid"):
                break
            time.sleep(0.5)
        if order["status"] == "invalid":
            raise AcmeError(403, order.get("error", {"detail": "order invalid"}))
        _, _, order = self._post(order["finalize"], {"csr": b64(csr_der)})
        return dict(order)

    def get_request_status(self, request_id: str) -> dict[str, str]:
        _, _, o = self._post(request_id, None)
        return {"status": str(o.get("status"))}


def csr_der(pem: bytes) -> bytes:
    return x509.load_pem_x509_csr(pem).public_bytes(serialization.Encoding.DER)


def csr_domains(pem: bytes) -> list[str]:
    csr = x509.load_pem_x509_csr(pem)
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
        if names:
            return list(names)
    except x509.ExtensionNotFound:
        pass
    cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return [str(cn[0].value)] if cn else ["example.test"]
