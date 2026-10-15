from __future__ import annotations

import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from pkisage.models import ErrorCategory, Finding, Severity
from pkisage.netutil import open_url

from .parse import load_cert_obj, parse_cert


def check_ocsp(cert_path: Path, issuer_path: Path | None, timeout: float = 5.0) -> list[Finding]:
    cert = load_cert_obj(cert_path.read_bytes())
    info = parse_cert(cert)
    findings: list[Finding] = []
    if not info.ocsp_urls:
        findings.append(Finding(
            rule_id="ocsp-url", severity=Severity.WARN, message="No OCSP URL in AIA",
            evidence="AIA has no OCSP responder",
            fix="Check the certificate profile includes AIA OCSP."))
    else:
        findings.append(Finding(
            rule_id="ocsp-url", severity=Severity.PASS, message="OCSP URL present",
            evidence=info.ocsp_urls[0]))
    if info.crl_urls:
        findings.append(Finding(
            rule_id="crl-url", severity=Severity.PASS, message="CRL URL present",
            evidence=info.crl_urls[0]))
    if not info.ocsp_urls or issuer_path is None:
        if info.ocsp_urls:
            findings.append(Finding(
                rule_id="ocsp-query", severity=Severity.WARN,
                message="Issuer not supplied; OCSP query skipped",
                evidence="use --issuer issuer.pem"))
        return findings
    issuer = load_cert_obj(issuer_path.read_bytes())
    # SHA-1 here is the RFC 6960 CertID hash that responders expect, not a security use.
    cert_id_hash = hashes.SHA1()  # nosec B303
    req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, cert_id_hash).build()
    url = info.ocsp_urls[0]
    if not url.startswith(("http://", "https://")):
        return findings
    try:
        http_req = urllib.request.Request(
            url, data=req.public_bytes(serialization.Encoding.DER),
            headers={"Content-Type": "application/ocsp-request"})
        with open_url(http_req, timeout=timeout) as resp:
            body = resp.read()
        r = ocsp.load_der_ocsp_response(body)
    except Exception as e:  # network/parse errors are findings, not crashes
        findings.append(Finding(
            rule_id="ocsp-query", severity=Severity.FAIL, category=ErrorCategory.UNKNOWN,
            message="OCSP responder unreachable or invalid response", evidence=str(e),
            fix="Check network/firewall access to the responder and its health."))
        return findings
    if r.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        findings.append(Finding(
            rule_id="ocsp-query", severity=Severity.FAIL, category=ErrorCategory.UNKNOWN,
            message="OCSP responder returned error", evidence=r.response_status.name))
        return findings
    status = r.certificate_status
    revoked = status == ocsp.OCSPCertStatus.REVOKED
    findings.append(Finding(
        rule_id="ocsp-status", severity=Severity.FAIL if revoked else Severity.PASS,
        category=ErrorCategory.REVOKED if revoked else None,
        message="Certificate status", evidence=status.name,
        fix="Reissue the certificate." if revoked else ""))
    return findings


__all__ = ["check_ocsp", "x509"]
