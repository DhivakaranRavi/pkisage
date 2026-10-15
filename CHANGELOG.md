# Changelog

## 0.1.0 (unreleased alpha)
- CLI: `preflight`, `cert`, `chain`, `ocsp`, `explain`, `migrate-check`, `log`, `triage`, `diagnose`, `reply`, `kb draft`, `enroll-check`, `metrics`, `acme-probe`, `serve`, `ai-eval`, and `jira triage|diagnose|comment|create`.
- Decision layer with a pinned Jev model, rule-based fallback, caching, and confidence routing.
- Redaction, prompt-injection guard, and citation-based reply validation.
- PQC readiness warning for RSA/EC keys (NIST IR 8547).
- Prometheus certificate-expiry metrics.
- Error library: 25 entries, 12 verified against real CAs (step-ca, Pebble, EJBCA CE); entries show verified|documented|unverified.
- Held-out evaluation (46 public-source items, frozen) and docs/eval.md.
- Podman lab (step-ca, Pebble, EJBCA CE) and a bench against a real CA.
- Known limits: EJBCA/DigiCert adapters are tested against fakes only; labeled evaluation data is synthetic.
- Auto-routing is opt-in (`PKISAGE_TRUST_AUTO=1`); a second held-out set (real GitHub issue titles); JSON-mode citation parsing; `metrics` and systemd units verified on Rocky Linux 9.
