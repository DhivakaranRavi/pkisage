from __future__ import annotations

import http.server
import socketserver
from collections.abc import Iterable
from pathlib import Path

from cryptography import x509

from .checks.parse import load_cert_obj, now, parse_cert

CERT_EXT = {".pem", ".crt", ".cer"}


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _certs_in(paths: Iterable[Path]) -> list[tuple[Path, x509.Certificate]]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.suffix.lower() in CERT_EXT)
        else:
            files.append(p)
    out: list[tuple[Path, x509.Certificate]] = []
    for f in files:
        data = f.read_bytes()
        try:
            certs = (
                x509.load_pem_x509_certificates(data)
                if b"-----BEGIN CERT" in data
                else [load_cert_obj(data)]
            )
        except ValueError:
            continue
        out += [(f, c) for c in certs]
    return out


def render(paths: Iterable[Path]) -> str:
    days_l = [
        "# HELP pkisage_cert_expiry_days Days until the certificate expires (negative if expired).",
        "# TYPE pkisage_cert_expiry_days gauge",
    ]
    ts_l = [
        "# HELP pkisage_cert_not_after_timestamp_seconds Expiry as a Unix timestamp.",
        "# TYPE pkisage_cert_not_after_timestamp_seconds gauge",
    ]
    pq_l = [
        "# HELP pkisage_cert_quantum_vulnerable 1 if the public key is breakable by Shor's algorithm.",
        "# TYPE pkisage_cert_quantum_vulnerable gauge",
    ]
    for f, cert in _certs_in(paths):
        info = parse_cert(cert)
        assert info.not_after is not None
        labels = (
            f'file="{_esc(f.name)}",subject="{_esc(info.subject)}",issuer="{_esc(info.issuer)}"'
        )
        days = (info.not_after - now()).total_seconds() / 86400
        days_l.append(f"pkisage_cert_expiry_days{{{labels}}} {days:.2f}")
        ts = int(info.not_after.timestamp())
        ts_l.append(f"pkisage_cert_not_after_timestamp_seconds{{{labels}}} {ts}")
        pq_l.append(f"pkisage_cert_quantum_vulnerable{{{labels}}} {1 if info.pq_vulnerable else 0}")
    return "\n".join(days_l + ts_l + pq_l) + "\n"


def serve(paths: list[Path], host: str, port: int) -> None:
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            body = render(paths).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    with socketserver.TCPServer((host, port), H) as srv:
        srv.serve_forever()
