# Lab findings (real CAs)

All results come from local lab CAs run in podman. They show how real CAs behave, not what any particular enterprise policy is.

| CA | Version | What was tested |
|---|---|---|
| step-ca | `smallstep/step-ca:latest` (Oct 2026) | 12 CSR variants via `step ca sign`; real error messages |
| Pebble | v2.10.1 | ACME orders via `pkisage acme-probe`; real problem documents |
| EJBCA Community Edition | `keyfactor/ejbca-ce:latest`, image 45aad12c3009 (2026-10-14) | End-entity enrollment via `ejbca.sh ra addendentity` and `createcert` |

## Key finding: a CA's defaults are often looser than a company policy
- **step-ca** rejected only 1 of 12 CSR variants (RSA 1024). It accepted a CSR with no SAN, P-521, SHA-1 signature and a client-auth EKU.
- **EJBCA CE**: in this lab, with the default `ENDUSER` certificate profile and no profile changes, EJBCA accepted **all 5** test CSRs, including **RSA 512** and a CSR with no SAN. This describes the lab's default profile, not EJBCA's capabilities: EJBCA can enforce key-size and SAN rules, but only if the certificate profile is configured to, and real deployments use stricter profiles.
- The example `corp-web` preflight policy flagged: RSA 1024 (`key-size`), RSA 512 (`key-size`, `san-present`), no SAN (`san-present`), P-521 (`curve`, `san-present`).

So preflight is most valuable as a check of **your policy** before submission, since a lenient CA will not reject a request that your policy (or a later migration to a stricter CA) will.

## What the verified error entries cover
6 entries from step-ca/Pebble and 6 from EJBCA CE (credentials, unknown user, enrollment status, not PKCS#10, unknown CA, duplicate user). EJBCA key-size and SAN errors are **not** verified: they require a stricter certificate profile than the default.

## Caveats
Single runs on one date, default configurations, one image digest each. Re-verify on your own CA version before trusting an entry.
