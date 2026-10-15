# Threat model

## Assets
Customer certificate requests and certificates, support tickets and logs (may contain secrets or personal data), CA and Jira credentials, AI provider keys.

## Trust boundaries
1. **Untrusted input:** ticket text, attachments, logs, CSRs/certificates, CA error text. Treated as data only.
2. **External AI providers (Jev, a chat model):** receive only redacted text. Local models (Ollama) avoid this boundary.
3. **Jira and CAs:** reached with least-privilege credentials from the environment.

## Threats and mitigations
| Threat | Mitigation | Tested |
|---|---|---|
| Secrets or PII leak to an AI provider | Redaction (private keys, passwords, PINs, tokens, bearer values, emails) at the provider boundary and when parsing logs | `test_secrets_never_reach_models` |
| Prompt injection in tickets/logs changes behavior | Suspected injection forces human routing; model output is data; replies must cite verified facts and uncited sentences are dropped | `test_injection_*`, `test_cited_reply_*` |
| Model invents facts or fixes | Fixes come only from deterministic rules; replies validated; template fallback when validation fails | `test_cited_reply_*`, `test_template_fallback_*` |
| Tool changes a CA | Production adapters are GET-only; ACME client is lab-only | `test_adapters_are_read_only` |
| Unintended Jira writes | Dry run by default; `--post` required; attachments limited to certificate/log types and 5 MB | `test_jira_diagnose_cli_dry_run_then_post` |
| Malicious attachment names (path traversal) | Filenames sanitized to a basename | `test_diagnose_ticket_pipeline` |
| Credential exposure | `.env` git-ignored; secrets never logged; rotate keys that were pasted anywhere | manual |
| Malformed certificates crash the tool | Parse errors become clean `error:` messages, exit 2 | CLI tests |

## Residual risks
- Redaction is pattern-based and can miss unusual secret formats. Review before enabling hosted AI on real data.
- Jev and chat providers are third parties; complete a security/privacy review first.
- Classifier errors occur even when auto-routed (see [eval.md](eval.md)).
- Alpha software; not production-hardened.
