from __future__ import annotations

from pathlib import Path

import yaml

from pkisage.models import ErrorCategory, Finding, Profile, Severity

from .parse import ParsedObject, now

PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"


def load_profile(path: str | Path) -> Profile:
    p = Path(path)
    if not p.exists() and (PROFILE_DIR / p.name).exists():
        p = PROFILE_DIR / p.name
    data = yaml.safe_load(p.read_text())
    return Profile.model_validate(data)


def evaluate(obj: ParsedObject, profile: Profile) -> list[Finding]:
    out: list[Finding] = []

    def add(
        rule: str, ok: bool, cat: ErrorCategory, msg: str, evidence: str, fix: str,
        sev: Severity = Severity.FAIL,
    ) -> None:
        out.append(
            Finding(
                rule_id=rule,
                severity=Severity.PASS if ok else sev,
                category=None if ok else cat,
                message=msg,
                evidence=evidence,
                fix="" if ok else fix,
            )
        )

    add("key-type", obj.key_type in profile.allowed_key_types, ErrorCategory.KEY_TYPE_NOT_ALLOWED,
        "Key type allowed", f"key type {obj.key_type}; allowed {profile.allowed_key_types}",
        f"Generate a key of type {'/'.join(profile.allowed_key_types)}.")

    if obj.key_type == "RSA":
        add("key-size", obj.key_bits >= profile.min_rsa_bits, ErrorCategory.KEY_TOO_WEAK,
            "RSA key size meets minimum", f"{obj.key_bits} bits; minimum {profile.min_rsa_bits}",
            f"openssl genrsa -out key.pem {max(profile.min_rsa_bits, 3072)}")
    elif obj.key_type == "EC":
        add("curve", (obj.curve or "") in profile.allowed_curves, ErrorCategory.KEY_TOO_WEAK,
            "EC curve allowed", f"curve {obj.curve}; allowed {profile.allowed_curves}",
            "openssl ecparam -genkey -name prime256v1 -out key.pem")

    if profile.san_required:
        add("san-present", bool(obj.san), ErrorCategory.SAN_MISSING, "SAN present",
            f"SAN: {obj.san or 'none'}",
            'openssl req -new -key key.pem -addext "subjectAltName=DNS:host.example.com"')

        if obj.san:
            dns = [n for n in obj.san if n.startswith("DNS:")]
            add("san-dns", bool(dns), ErrorCategory.SAN_MISSING, "SAN has a DNS name",
                f"SAN: {obj.san}",
                'Add a DNS SAN, e.g. -addext "subjectAltName=DNS:host.example.com" '
                "(IP-only SANs are rejected by ACME CAs).")

    if obj.ekus:
        bad = [e for e in obj.ekus if e not in profile.allowed_ekus]
        add("eku-allowed", not bad, ErrorCategory.EKU_NOT_ALLOWED, "EKUs allowed",
            f"EKU {obj.ekus}; disallowed {bad}; allowed {profile.allowed_ekus}",
            f"Remove {bad} from the request.")

    add("sig-alg", obj.sig_hash in profile.allowed_sig_algs, ErrorCategory.SIG_ALG_REJECTED,
        "Signature algorithm allowed",
        f"hash {obj.sig_hash}; allowed {profile.allowed_sig_algs}",
        "Re-sign with SHA-256 or stronger (openssl req -new -sha256 ...).")

    if obj.kind == "csr":
        add("csr-signature", obj.sig_valid, ErrorCategory.UNKNOWN, "CSR signature valid",
            f"signature valid: {obj.sig_valid}", "Regenerate the CSR; it is corrupt or tampered.")

    vd = obj.validity_days
    if vd is not None and profile.max_validity_days is not None:
        add("validity", vd <= profile.max_validity_days, ErrorCategory.VALIDITY_TOO_LONG,
            "Validity within maximum", f"{vd} days; maximum {profile.max_validity_days}",
            "Request a shorter validity period.")
    if obj.pq_vulnerable:
        out.append(Finding(
            rule_id="pqc-readiness", severity=Severity.WARN,
            message="Key algorithm is quantum-vulnerable",
            evidence=f"{obj.key_type}-{obj.key_bits}: breakable by Shor's algorithm; NIST IR 8547 "
                     "plans to deprecate RSA/ECC by 2030 and disallow them by 2035",
            fix="Inventory this key; plan migration to ML-DSA/ML-KEM (FIPS 204/203) or a hybrid "
                "scheme once your CA supports it."))
    if obj.not_after is not None:
        add("not-expired", obj.not_after > now(), ErrorCategory.CERT_EXPIRED,
            "Certificate not expired", f"notAfter {obj.not_after.isoformat()}",
            "Renew the certificate.")
    return out


def has_failures(findings: list[Finding]) -> bool:
    return any(f.severity == Severity.FAIL for f in findings)
