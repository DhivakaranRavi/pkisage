from __future__ import annotations

import warnings
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.utils import CryptographyDeprecationWarning

from pkisage.models import ErrorCategory, Finding, Severity

from .parse import load_cert_obj, now


def load_bundle(path: Path) -> list[x509.Certificate]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return x509.load_pem_x509_certificates(path.read_bytes())


def _der(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.DER)


def _signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    if child.issuer != parent.subject:
        return False
    pub = parent.public_key()
    hash_alg = child.signature_hash_algorithm
    if hash_alg is None:
        return False
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), hash_alg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(hash_alg))
        else:
            return False
    except Exception:
        return False
    return True


def check_chain(leaf_path: Path, bundle_path: Path) -> list[Finding]:
    leaf_data = leaf_path.read_bytes()
    if b"-----BEGIN" in leaf_data:
        certs = x509.load_pem_x509_certificates(leaf_data)
    else:
        certs = [load_cert_obj(leaf_data)]
    leaf, extra = certs[0], certs[1:]
    anchors = load_bundle(bundle_path)
    trusted = {_der(c) for c in anchors}
    pool = anchors + extra
    findings: list[Finding] = []
    current = leaf
    path_desc = [leaf.subject.rfc4514_string()]
    for _ in range(10):
        if _der(current) in trusted:
            findings.append(Finding(
                rule_id="chain-trusted", severity=Severity.PASS,
                message="Chain reaches trust anchor", evidence=" -> ".join(path_desc)))
            break
        if current.not_valid_after_utc < now():
            findings.append(Finding(
                rule_id="chain-expired", severity=Severity.FAIL,
                category=ErrorCategory.CERT_EXPIRED, message="Certificate in chain expired",
                evidence=current.subject.rfc4514_string(), fix="Renew the expired certificate."))
            break
        parent = next((p for p in pool if p is not current and _signed_by(current, p)), None)
        if parent is None:
            msg = (
                "Self-signed root not in CA bundle"
                if current.issuer == current.subject
                else "Missing intermediate/issuer"
            )
            findings.append(Finding(
                rule_id="chain-complete", severity=Severity.FAIL,
                category=ErrorCategory.CHAIN_UNTRUSTED, message=msg,
                evidence=f"issuer not found: {current.issuer.rfc4514_string()}",
                fix="Serve the issuing intermediate with the leaf and add the root to the bundle."))
            break
        path_desc.append(parent.subject.rfc4514_string())
        current = parent
    else:
        findings.append(Finding(
            rule_id="chain-depth", severity=Severity.FAIL, category=ErrorCategory.CHAIN_UNTRUSTED,
            message="Chain too deep", evidence=" -> ".join(path_desc)))
    return findings
