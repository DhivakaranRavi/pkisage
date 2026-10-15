from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "emailProtection",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "OCSPSigning",
}


@dataclass
class ParsedObject:
    kind: str  # "csr" or "cert"
    subject: str
    key_type: str
    key_bits: int
    curve: str | None
    san: list[str] = field(default_factory=list)
    ekus: list[str] = field(default_factory=list)
    key_usage: list[str] = field(default_factory=list)
    sig_hash: str = ""
    sig_valid: bool = True
    not_before: datetime | None = None
    not_after: datetime | None = None
    issuer: str = ""
    is_ca: bool | None = None
    ocsp_urls: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)

    @property
    def pq_vulnerable(self) -> bool:
        # Shor's algorithm breaks RSA, DSA and all elliptic-curve keys (incl. Ed25519/Ed448).
        return self.key_type in {"RSA", "EC", "DSA", "Ed25519", "Ed448"}

    @property
    def validity_days(self) -> int | None:
        if self.not_before and self.not_after:
            return (self.not_after - self.not_before).days
        return None


def _key_info(pub: object) -> tuple[str, int, str | None]:
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size, None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.key_size, pub.curve.name
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 456, None
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size, None
    return "UNKNOWN", 0, None


def _hash_name(obj: x509.Certificate | x509.CertificateSigningRequest) -> str:
    h = obj.signature_hash_algorithm
    return h.name if h else "none"


def _eku_list(ext_values: list[x509.ObjectIdentifier]) -> list[str]:
    return [EKU_NAMES.get(o.dotted_string, o.dotted_string) for o in ext_values]


def _san_list(exts: x509.Extensions) -> list[str]:
    try:
        ext = exts.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san = ext.value
    assert isinstance(san, x509.SubjectAlternativeName)
    return [f"DNS:{v}" for v in san.get_values_for_type(x509.DNSName)] + [
        f"IP:{v}" for v in san.get_values_for_type(x509.IPAddress)
    ]


def _try(exts: x509.Extensions, oid: x509.ObjectIdentifier) -> x509.ExtensionType | None:
    try:
        return exts.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def load_csr(data: bytes) -> ParsedObject:
    csr = (
        x509.load_pem_x509_csr(data) if b"-----BEGIN" in data else x509.load_der_x509_csr(data)
    )
    kt, bits, curve = _key_info(csr.public_key())
    eku = _try(csr.extensions, ExtensionOID.EXTENDED_KEY_USAGE)
    return ParsedObject(
        kind="csr",
        subject=csr.subject.rfc4514_string(),
        key_type=kt,
        key_bits=bits,
        curve=curve,
        san=_san_list(csr.extensions),
        ekus=_eku_list(list(eku)) if isinstance(eku, x509.ExtendedKeyUsage) else [],
        sig_hash=_hash_name(csr),
        sig_valid=csr.is_signature_valid or _hash_name(csr) == "sha1",
    )


def load_cert_obj(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data else (
        x509.load_der_x509_certificate(data)
    )


def parse_cert(cert: x509.Certificate) -> ParsedObject:
    kt, bits, curve = _key_info(cert.public_key())
    exts = cert.extensions
    eku = _try(exts, ExtensionOID.EXTENDED_KEY_USAGE)
    bc = _try(exts, ExtensionOID.BASIC_CONSTRAINTS)
    ku = _try(exts, ExtensionOID.KEY_USAGE)
    aia = _try(exts, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    crl = _try(exts, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    ocsp_urls: list[str] = []
    if isinstance(aia, x509.AuthorityInformationAccess):
        ocsp_urls = [
            d.access_location.value
            for d in aia
            if d.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
        ]
    crl_urls: list[str] = []
    if isinstance(crl, x509.CRLDistributionPoints):
        for dp in crl:
            for n in dp.full_name or []:
                if isinstance(n, x509.UniformResourceIdentifier):
                    crl_urls.append(n.value)
    usages: list[str] = []
    if isinstance(ku, x509.KeyUsage):
        for name in ("digital_signature", "key_encipherment", "key_cert_sign", "crl_sign"):
            if getattr(ku, name):
                usages.append(name)
    return ParsedObject(
        kind="cert",
        subject=cert.subject.rfc4514_string(),
        key_type=kt,
        key_bits=bits,
        curve=curve,
        san=_san_list(exts),
        ekus=_eku_list(list(eku)) if isinstance(eku, x509.ExtendedKeyUsage) else [],
        key_usage=usages,
        sig_hash=_hash_name(cert),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        issuer=cert.issuer.rfc4514_string(),
        is_ca=bc.ca if isinstance(bc, x509.BasicConstraints) else None,
        ocsp_urls=ocsp_urls,
        crl_urls=crl_urls,
    )


def load_any(path: Path) -> ParsedObject:
    data = path.read_bytes()
    if b"CERTIFICATE REQUEST" in data:
        return load_csr(data)
    try:
        return parse_cert(load_cert_obj(data))
    except ValueError:
        return load_csr(data)


def now() -> datetime:
    return datetime.now(timezone.utc)
