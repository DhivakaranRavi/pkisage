from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_csr(
    path: Path, bits: int = 3072, san: bool = True, eku: bool = False, h: hashes.HashAlgorithm | None = None,
    ec_key: bool = False,
) -> Path:
    key = ec.generate_private_key(ec.SECP256R1()) if ec_key else rsa.generate_private_key(65537, bits)
    b = x509.CertificateSigningRequestBuilder().subject_name(_name("app.example.com"))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName("app.example.com")]), False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
    csr = b.sign(key, h or hashes.SHA256())
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return path


def make_cert(
    subject: str, issuer: str, key: rsa.RSAPrivateKey, signer: rsa.RSAPrivateKey,
    ca: bool = False, days: int = 90, san: bool = False,
) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    b = (
        x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    )
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(subject)]), False)
    return b.sign(signer, hashes.SHA256())


def pem(*certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


@pytest.fixture
def pki(tmp_path: Path) -> dict[str, Path]:
    rk, ik, lk = (rsa.generate_private_key(65537, 2048) for _ in range(3))
    root = make_cert("Root", "Root", rk, rk, ca=True, days=3650)
    inter = make_cert("Inter", "Root", ik, rk, ca=True, days=1800)
    leaf = make_cert("app.example.com", "Inter", lk, ik, san=True)
    out = {
        "bundle": tmp_path / "bundle.pem",
        "leaf": tmp_path / "leaf.pem",
        "full": tmp_path / "full.pem",
        "inter": tmp_path / "inter.pem",
    }
    out["bundle"].write_bytes(pem(root))
    out["leaf"].write_bytes(pem(leaf))
    out["full"].write_bytes(pem(leaf, inter))
    out["inter"].write_bytes(pem(inter))
    return out


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKISAGE_CACHE_DIR", str(tmp_path / "cache"))
