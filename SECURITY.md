# Security policy

pkisage handles certificate requests, logs and support tickets that may contain sensitive data.

## Reporting a vulnerability
Please report suspected vulnerabilities privately (GitHub "Report a vulnerability" on the repository's Security tab, once published) instead of opening a public issue. Include the version, steps to reproduce, and impact.

## Design guarantees
- **Read-only against CAs.** The production adapters (`adapters/rest.py`) only issue HTTP GET. The ACME client (`adapters/acme.py`) writes to a CA and is for lab/test CAs only.
- **Redaction before any external model call** (private keys, passwords, PINs, tokens, bearer values, emails). Covered by `tests/test_hardening.py`.
- **Jira writes are opt-in.** `jira diagnose` and `jira comment` are dry runs unless `--post` is given.
- **LLM output is never authoritative.** Facts come from deterministic checks; replies must cite numbered facts and uncited sentences are dropped. Suspected prompt injection is never auto-routed.
- **Secrets live in the environment or a git-ignored `.env`**, never in the repository.

## Not guaranteed
pkisage is an alpha, not production-hardened. Review the [threat model](docs/threat-model.md) before processing real customer data, and complete your own security and privacy review before enabling any hosted AI provider.
