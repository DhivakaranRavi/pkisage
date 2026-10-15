from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel

from pkisage.ai.redact import redact
from pkisage.models import ErrorCategory

# (id, regex, category, source, cause, fix) - illustrative generic patterns.
PATTERNS: list[tuple[str, str, ErrorCategory, str, str, str]] = [
    ("tomcat-keystore", r"(?i)keystore was tampered|Keystore.*password was incorrect",
     ErrorCategory.AUTH_FAILED, "tomcat", "Wrong keystore password or corrupt keystore.",
     "Verify keystorePass in server.xml and the keystore integrity with keytool -list."),
    ("tomcat-handshake", r"(?i)PKIX path (building|validation) failed|unable to find valid certification path",
     ErrorCategory.CHAIN_UNTRUSTED, "tomcat", "Peer chain is not trusted by the JVM truststore.",
     "Import the issuing CA into the truststore or serve the full chain."),
    ("tomcat-expired", r"(?i)CertificateExpiredException|NotAfter",
     ErrorCategory.CERT_EXPIRED, "tomcat", "A certificate in the path has expired.",
     "Renew the expired certificate."),
    ("ocsp-unauthorized", r"(?i)ocsp.*(unauthorized|status 6)|responder.*unauthorized",
     ErrorCategory.AUTH_FAILED, "ocsp", "OCSP responder rejected the request signer/issuer.",
     "Check responder issuer config and that the request names a known issuer."),
    ("ocsp-timeout", r"(?i)ocsp.*(timed? ?out|connection refused)",
     ErrorCategory.UNKNOWN, "ocsp", "OCSP responder unreachable.",
     "Check responder health and firewall rules."),
    ("hsm-pin", r"(?i)CKR_PIN_(INCORRECT|LOCKED|EXPIRED)|CKR_USER_NOT_LOGGED_IN",
     ErrorCategory.AUTH_FAILED, "hsm", "HSM login failed (PKCS#11).",
     "Verify the crypto-token PIN/slot and unlock the token; avoid retries that lock it."),
    ("hsm-session", r"(?i)CKR_(SESSION_HANDLE_INVALID|DEVICE_ERROR|TOKEN_NOT_PRESENT)",
     ErrorCategory.UNKNOWN, "hsm", "HSM session/device problem.",
     "Check HSM connectivity and restart the crypto token."),
    ("ca-san", r"(?i)subject alternative name.*(missing|required)",
     ErrorCategory.SAN_MISSING, "ca", "Request rejected for missing SAN.",
     "Add a SAN to the CSR."),
    ("ca-key", r"(?i)key (length|size).*(too (short|small)|not allowed)",
     ErrorCategory.KEY_TOO_WEAK, "ca", "Key below profile minimum.", "Use a stronger key."),
    ("ca-sigalg", r"(?i)signature algorithm.*(not (allowed|supported)|rejected)",
     ErrorCategory.SIG_ALG_REJECTED, "ca", "Signature algorithm rejected.", "Re-sign with SHA-256+."),
    ("ca-validity", r"(?i)validity.*(exceed|too long)",
     ErrorCategory.VALIDITY_TOO_LONG, "ca", "Validity exceeds profile.", "Shorten validity."),
    ("ca-revoked", r"(?i)certificate.*revoked",
     ErrorCategory.REVOKED, "ca", "Certificate is revoked.", "Reissue the certificate."),
]


class LogMatch(BaseModel):
    pattern_id: str
    source: str
    category: ErrorCategory
    line_no: int
    line: str
    cause: str
    fix: str


def parse_log(path: Path) -> list[LogMatch]:
    matches: list[LogMatch] = []
    compiled = [(p, re.compile(p[1])) for p in PATTERNS]
    for no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        for p, rx in compiled:
            if rx.search(line):
                matches.append(LogMatch(
                    pattern_id=p[0], source=p[3], category=p[2], line_no=no,
                    line=redact(line.strip())[:300], cause=p[4], fix=p[5]))
    return matches
