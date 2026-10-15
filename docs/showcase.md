# Showcase guide

## 3-minute walkthrough (for a reviewer or interviewer)
Run `./demo.sh` (about a minute). It tells one story: *a customer's CSR worked on the old CA and fails after cutover.*
1. `migrate-check`: which apps break on the new platform and why.
2. `preflight`: the failing rule, the evidence, and the exact fix command.
3. `explain`: the CA's raw error translated into a cause and fix, labeled verified / unverified.
4. `diagnose`: root cause, evidence, fix, confidence (`verified: true` only when backed by deterministic checks).
5. `reply`: a customer message drafted from verified facts only; a human approves it.

Then show the real-CA evidence: `docs/lab-findings.md` (what step-ca, EJBCA CE and Pebble actually did) and `tests/data/real_ca_errors.json`.

## Talking points (what to say about the design)
- **Deterministic first, AI second.** The rules decide the facts; Jev only classifies when no rule matches; the chat model only words a reply, and every sentence must cite a verified fact.
- **Read-only against CAs.** It diagnoses; it never issues, revokes or changes a CA.
- **Honest numbers.** Two frozen held-out sets, a paired test, and the limits written down (labels are AI-assigned and unreviewed; confidence is poor on non-error text, so auto-routing is off).
- **Things testing found.** CAs' defaults are looser than company policy (EJBCA's default profile accepted RSA 512); IP-only SANs passed my own rule until Pebble rejected them; a packaging bug only showed on a clean Rocky Linux machine.

## Resume wording (keep it to what is true)
- Built an AI-assisted PKI diagnostics tool (Python): certificate/CSR pre-flight against configurable profiles, chain and OCSP checks, migration pre-checks, and Jira ticket triage with verifiable evidence.
- Reproduced and catalogued CA failures on step-ca, EJBCA CE and an ACME test CA in a podman lab; 12 error entries verified against real CA output.
- Evaluated an LLM-based classifier on two frozen held-out sets with a paired McNemar test; disabled auto-routing after finding confident wrong answers.
- Added PQC-readiness flags, Prometheus expiry metrics, and RHEL-compatible packaging, tested on Rocky Linux 9.

## Be ready for these questions
- "How do you know the error text is right?" Only 12 of 25 entries are reproduced on a real CA; the rest are labeled unverified.
- "Why not let the LLM write the fix?" A fix is a decision; wrong commands can cause outages, so fixes come from tested rules.
- "What would you do differently in production?" A non-production CA that mirrors production profiles, secrets in a vault, HSM-backed keys, expert-reviewed labels, and real (anonymized) tickets for evaluation.

## Before sharing publicly
Rotate any keys that were ever pasted anywhere, and keep `.env` and notes files out of git. Verify the claims in the README table still match what you can demonstrate live.
