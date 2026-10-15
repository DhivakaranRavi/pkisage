# Error-entry format

Entries live in `src/pkisage/errors/<ca>.yaml` as a list. Each is validated by the `ErrorEntry` model.

```yaml
- id: stepca-rsa-key-small          # unique, <ca>-<slug>
  pattern: "RSA key must be at least \\d+ bits"   # Python regex, searched in the raw error text
  category: KEY_TOO_WEAK            # an ErrorCategory enum value
  cause: One sentence on why the CA rejects this.
  fix: The concrete action the requester takes.
  verified_against: step-ca-latest  # set ONLY after a lab reproduction (see verifying-entries.md)
  source: https://...               # optional documentation URL
```

## Status shown in output
- **verified:** `verified_against` is set (reproduced on a real CA).
- **documented:** `source` is set but no reproduction.
- **unverified:** neither. Treat the text as a hint.

Rules: keep patterns specific, add a negative lookahead if a more specific entry should win, and add the captured real message to `tests/data/real_ca_errors.json` for any verified entry.
