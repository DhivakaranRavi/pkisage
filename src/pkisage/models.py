from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class ErrorCategory(str, Enum):
    SAN_MISSING = "SAN_MISSING"
    KEY_TOO_WEAK = "KEY_TOO_WEAK"
    KEY_TYPE_NOT_ALLOWED = "KEY_TYPE_NOT_ALLOWED"
    EKU_NOT_ALLOWED = "EKU_NOT_ALLOWED"
    VALIDITY_TOO_LONG = "VALIDITY_TOO_LONG"
    SIG_ALG_REJECTED = "SIG_ALG_REJECTED"
    CHAIN_UNTRUSTED = "CHAIN_UNTRUSTED"
    CERT_EXPIRED = "CERT_EXPIRED"
    VALIDATION_PENDING = "VALIDATION_PENDING"
    REVOKED = "REVOKED"
    AUTH_FAILED = "AUTH_FAILED"
    POLICY_REJECTED = "POLICY_REJECTED"
    UNKNOWN = "UNKNOWN"


class Profile(BaseModel):
    name: str
    allowed_key_types: list[str] = Field(default_factory=lambda: ["RSA", "EC"])
    min_rsa_bits: int = 2048
    allowed_curves: list[str] = Field(default_factory=lambda: ["secp256r1", "secp384r1"])
    san_required: bool = True
    allowed_ekus: list[str] = Field(default_factory=lambda: ["serverAuth"])
    max_validity_days: int | None = 397
    allowed_sig_algs: list[str] = Field(default_factory=lambda: ["sha256", "sha384", "sha512"])


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    category: ErrorCategory | None = None
    message: str
    evidence: str = ""
    fix: str = ""


class Decision(BaseModel):
    category: ErrorCategory
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[str] = Field(default_factory=list)
    route: str = "human"


class ErrorEntry(BaseModel):
    id: str
    pattern: str
    category: ErrorCategory
    cause: str
    fix: str
    verified_against: str | None = None
    source: str | None = None

    @property
    def status(self) -> str:
        if self.verified_against:
            return "verified"
        return "documented" if self.source else "unverified"


class DiagnosisReport(BaseModel):
    root_cause: str
    category: ErrorCategory
    evidence: list[str] = Field(default_factory=list)
    fix: str = ""
    confidence: float = 0.0
    verified: bool = False
