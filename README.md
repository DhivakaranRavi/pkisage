# pkisage

A read-only helper for PKI operations teams. It checks certificate requests before they reach a CA, predicts which apps break in a CA migration, translates CA errors and logs into causes and fixes, and diagnoses support tickets (including in Jira) with verifiable evidence. AI is used only to classify and to word replies; deterministic checks decide the facts and a human approves anything customer-facing.

> **Status: alpha (0.1.0).** Not production-hardened. It is not a CA and never changes a CA.

## Install
```
python3 -m venv .venv && .venv/bin/pip install -e .          # add '.[api]' for the REST API
cp .env.example .env                                           # optional: AI providers, Jira
```
RHEL-compatible install notes: [docs/rhel.md](docs/rhel.md) (tested on Rocky Linux 9.8).

## Commands
```
pkisage preflight request.csr --profile corp-web.yaml    # rules + PQC readiness warning
pkisage cert server.pem                                  # parsed fields (--json)
pkisage chain server.pem --ca-bundle ca.pem
pkisage ocsp server.pem --issuer issuer.pem
pkisage explain --ca stepca --error "<raw error>"        # prints verified | documented | unverified
pkisage migrate-check --old old.yaml --new new.yaml --input ./csrs/
pkisage log ca-server.log
pkisage enroll-check order.json                           # DigiCert-style order body (doc-derived)
pkisage metrics /etc/pki/tls/certs [--serve 9100]         # Prometheus days-to-expiry
pkisage triage --ticket ticket.txt
pkisage diagnose --ticket t.txt --csr r.csr --log app.log [--json|--jira]
pkisage reply --from report.json                          # LLM draft, validated; falls back to a template
pkisage kb draft --from report.json [--llm]
pkisage jira triage|diagnose|comment|create ...           # dry run unless --post
pkisage acme-probe r.csr --directory https://127.0.0.1:14000/dir --insecure   # lab CA only
pkisage ai-eval tests/data/heldout.jsonl --heldout --model jev
pkisage serve                                             # REST API (pip install '.[api]')
```
`./demo.sh` runs the one-minute story end to end.

## What is verified, and what is not
| Area | Status |
|---|---|
| Preflight (10 rules), chain, OCSP, parsing | Tested; OCSP and chain also run live against github.com and microsoft.com; `cert` cross-checked with `openssl` and `step certificate inspect` |
| Error library | 19 entries; **6 verified against real CAs** (step-ca, Pebble), 13 unverified. Output labels each. |
| Lab | Podman lab with **step-ca** and **Pebble** (not EJBCA). `lab/bench.py`: step-ca rejected 1 of 12 CSR variants and preflight flagged it; preflight also flagged 5 that step-ca accepts because the example `corp-web` policy is stricter. |
| Classifier | See [docs/eval.md](docs/eval.md): on two frozen held-out sets (46 documentation strings, 44 real GitHub issue titles; each run once), Jev scored 71.7% and 81.8%, rules 63.0% and 59.1%. Pooled N=90: Jev 76.7% (95% CI 66.9-84.2) vs rules 61.1% (50.8-70.5); intervals overlap slightly, so the advantage is suggestive only. Development-set scores (98% / 86%) are optimistic and not the headline. Labels were assigned by the author's AI assistant, unreviewed ([labeling rules](docs/labeling.md)). Auto-routing is **off by default** (3 of 27 high-confidence results were wrong); set `PKISAGE_TRUST_AUTO=1` to enable. |
| Migration | Demonstrated on generated sample CSRs only. |
| Jira | Triage and ticket enrichment (label + comment). No SLA/KPI tracking. Tested live on a personal Jira site and with a mocked Jira in the test suite. |
| CA adapters | ACME and step-ca verified in the lab. DigiCert and EJBCA clients are read-only and tested against fake servers only; `enroll-check` is derived from public docs. |
| Local model | Works end to end with Ollama (rule-based triage + local reply). A 0.5B model failed citation validation, so the template fallback was used. |
| RHEL | Install and core commands tested on Rocky Linux 9.8. systemd timer files are untested. |

## AI safeguards
Redaction before any external call (tested); suspected prompt injection is never auto-routed; replies must cite numbered facts and uncited/unsupported sentences are dropped (template fallback); Jev pinned to `jev-1.13.0`; results cached (`PKISAGE_NO_CACHE=1` to disable); Jira writes need `--post`; only http(s) URLs are opened; production adapters are GET-only. Details: [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md).

## Mapping to a PKI operations role (what it covers and what it does not)
| Covers | Does not cover |
|---|---|
| AI tools for PKI diagnostics, triage, log analysis | RHEL administration, patching, capacity planning |
| Migration pre-checks and per-app results | HSM installation and management (only HSM log parsing) |
| Ticket triage and enrichment in Jira | Running CAs/RAs, upgrades, on-call operations |
| X.509, chain, OCSP/CRL, TLS checks, PQC readiness flag | AWS Private CA / KMS / CloudHSM (no adapter) |
| Enrollment-request check, expiry metrics for monitoring | Windows Server, web-server and database administration |
| Runbook (KB) drafting | Certificate lifecycle management (by design, read-only) |

## Docs
[Profiles](docs/profiles.md) | [Error entries](docs/error-entries.md) | [Verifying entries](docs/verifying-entries.md) | [Evaluation](docs/eval.md) | [Threat model](docs/threat-model.md) | [RHEL](docs/rhel.md) | [Contributing](CONTRIBUTING.md) | [Changelog](CHANGELOG.md)

## Lab
`lab/up.sh` (Pebble ACME test CA), `lab/stepca-up.sh` (step-ca in podman; run `podman machine start` first), `lab/bench.py`. Lab CAs are for testing only (default settings, lab password, `--insecure` TLS); enterprises should test against a production-like non-production CA.

## License
Apache-2.0. See [LICENSE](LICENSE).
