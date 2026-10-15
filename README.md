# pkisage

```text
         _    _     _
  _ __  | | _(_)___  __ _  __ _  ___
 | '_ \ | |/ / / __|/ _` |/ _` |/ _ \
 | |_) ||   <| \__ \ (_| | (_| |  __/
 | .__/ |_|\_\_|___/\__,_|\__, |\___|
 |_|                      |___/
   read-only PKI diagnostics, migration checks & ticket triage
```

A read-only helper for PKI operations teams. It checks certificate requests before they reach a CA, predicts which apps break in a CA migration, translates CA errors and logs into causes and fixes, and diagnoses support tickets (including in Jira) with verifiable evidence. AI is used only to classify and to word replies; deterministic checks decide the facts and a human approves anything customer-facing.

> **Status: alpha (0.1.0).** Not production-hardened. It is not a CA and never changes a CA.
>
> **Evaluation caveat:** the labels behind the classifier numbers were assigned by an AI assistant and are not expert-reviewed, and the test data are documentation strings and public issue titles, not real tickets. See [docs/eval.md](docs/eval.md).

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
`./demo.sh` is a live, narrated demonstration (about 3 minutes); `./demo.sh --quick` runs the short migration story only. See [docs/showcase.md](docs/showcase.md).

## What is verified, and what is not
| Area | Status |
|---|---|
| Preflight (10 rules), chain, OCSP, parsing | Tested; OCSP and chain also run live against github.com and microsoft.com; `cert` cross-checked with `openssl` and `step certificate inspect` |
| Error library | 25 entries; **12 verified against real CAs** (step-ca, Pebble, EJBCA CE), 13 unverified. Output labels each. See [lab findings](docs/lab-findings.md). |
| Lab | Podman lab with **step-ca**, **Pebble** and **EJBCA CE** (default profiles; in this lab EJBCA's default profile accepted even RSA 512, which says nothing about what a configured profile enforces). `lab/bench.py`: step-ca rejected 1 of 12 CSR variants and preflight flagged it; preflight also flagged 5 that step-ca accepts because the example `corp-web` policy is stricter. |
| Classifier | Two frozen held-out sets (46 documentation strings, 44 GitHub issue titles). Paired re-run, pooled N=90: Jev 71/90 (78.9%) vs rules 55/90 (61.1%), McNemar p=0.026 (set 1 alone p=0.44, set 2 alone p=0.019); the first run gave Jev 69/90. Jev's answers vary by about one item between runs. Confidence is poorly calibrated on non-error text (0.91-1.00 on wrong answers), so auto-routing is **off by default** (`PKISAGE_TRUST_AUTO=1` enables). Development-set scores (98% / 86%) are optimistic. Labels are AI-assigned and unreviewed ([labeling](docs/labeling.md)). |
| Migration | Demonstrated on generated sample CSRs only. |
| Jira | Triage and ticket enrichment (label + comment). No SLA/KPI tracking. Tested live on a personal Jira site and with a mocked Jira in the test suite. |
| CA adapters | ACME and step-ca verified in the lab. DigiCert and EJBCA clients are read-only and tested against fake servers only; `enroll-check` is derived from public docs. |
| Local model | Works end to end with Ollama and no hosted API. A 0.5B model failed citation validation (template fallback used); **`qwen2.5:7b` passed 3 of 3 runs** with JSON mode. Classification locally is rule-based only. |
| RHEL | Install and core commands tested on Rocky Linux 9.8; systemd units pass `systemd-analyze verify` and the service command exported 146 certificates there. The timer itself was not run under a live systemd. |

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
[Profiles](docs/profiles.md) | [Error entries](docs/error-entries.md) | [Verifying entries](docs/verifying-entries.md) | [Evaluation](docs/eval.md) | [Labeling](docs/labeling.md) | [Lab findings](docs/lab-findings.md) | [Threat model](docs/threat-model.md) | [RHEL](docs/rhel.md) | [Contributing](CONTRIBUTING.md) | [Changelog](CHANGELOG.md)

## Lab
`lab/up.sh` (Pebble ACME test CA), `lab/stepca-up.sh` (step-ca in podman; run `podman machine start` first), `lab/ejbca-up.sh` (EJBCA CE; needs `podman machine set --memory 6144`), `lab/bench.py`. Lab CAs are for testing only (default settings, lab password, `--insecure` TLS); enterprises should test against a production-like non-production CA.

## License
Copyright 2026 Dhivakaran Ravi. Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
