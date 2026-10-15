"""Pre-flight validation of a CA enrollment (order) request body.

DigiCert CertCentral shape, derived from DigiCert's public API documentation
(POST /services/v2/order/certificate/{product}). Doc-derived, NOT lab-tested against a real
account: field names and rules may differ per product and account.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography import x509

from pkisage.checks.parse import load_csr
from pkisage.checks.preflight import evaluate
from pkisage.models import ErrorCategory, Finding, Profile, Severity

SOURCE = "doc-derived: DigiCert CertCentral REST API (order certificate)"
HASHES = {"sha256", "sha384", "sha512"}


def _f(rule: str, ok: bool, cat: ErrorCategory, msg: str, ev: str, fix: str) -> Finding:
    return Finding(rule_id=rule, severity=Severity.PASS if ok else Severity.FAIL,
                   category=None if ok else cat, message=msg, evidence=ev, fix="" if ok else fix)


def check_digicert_order(body: dict[str, Any], profile: Profile) -> list[Finding]:
    out: list[Finding] = []
    cert = body.get("certificate")
    if not isinstance(cert, dict):
        return [_f("enroll-certificate", False, ErrorCategory.UNKNOWN, "certificate object present",
                   "missing 'certificate' object", "Send a JSON body with a 'certificate' object.")]
    org = body.get("organization")
    out.append(_f("enroll-organization", isinstance(org, dict) and "id" in org,
                  ErrorCategory.UNKNOWN, "organization.id present",
                  f"organization: {org!r}", "Add organization: {\"id\": <validated org id>}."))
    out.append(_f("enroll-validity",
                  any(k in body for k in ("validity_years", "custom_expiration_date")),
                  ErrorCategory.VALIDITY_TOO_LONG, "validity specified",
                  "neither validity_years nor custom_expiration_date set",
                  "Set validity_years (for example 1) or custom_expiration_date."))
    sh = cert.get("signature_hash")
    out.append(_f("enroll-signature-hash", sh in HASHES, ErrorCategory.SIG_ALG_REJECTED,
                  "signature_hash allowed", f"signature_hash={sh!r}; allowed {sorted(HASHES)}",
                  "Use signature_hash: sha256 (or stronger)."))
    csr_pem = cert.get("csr")
    if not isinstance(csr_pem, str) or "BEGIN CERTIFICATE REQUEST" not in csr_pem:
        out.append(_f("enroll-csr", False, ErrorCategory.UNKNOWN, "PEM CSR present",
                      "certificate.csr missing or not PEM", "Embed the PEM CSR, newlines as \\n."))
        return out
    try:
        csr = load_csr(csr_pem.encode())
        raw = x509.load_pem_x509_csr(csr_pem.encode())
    except (ValueError, binascii.Error) as e:
        out.append(_f("enroll-csr", False, ErrorCategory.UNKNOWN, "CSR parses", str(e),
                      "Regenerate the CSR; it is not valid PEM/PKCS#10."))
        return out
    cn_attrs = raw.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    csr_cn = str(cn_attrs[0].value) if cn_attrs else ""
    body_cn = cert.get("common_name")
    out.append(_f("enroll-common-name", body_cn == csr_cn, ErrorCategory.SAN_MISSING,
                  "common_name matches the CSR", f"body={body_cn!r} csr={csr_cn!r}",
                  "Make certificate.common_name equal the CSR's CN."))
    names = {n.removeprefix("DNS:") for n in csr.san if n.startswith("DNS:")} | {csr_cn}
    extra = [d for d in cert.get("dns_names", []) if d not in names]
    out.append(_f("enroll-dns-names", not extra, ErrorCategory.SAN_MISSING,
                  "dns_names covered by the CSR", f"names not in CSR: {extra or 'none'}",
                  "Include every dns_names entry as a SAN in the CSR, or remove it from the request."))
    out += evaluate(csr, profile)
    return out


def decode_b64(s: str) -> str:
    return base64.b64decode(s).decode()
