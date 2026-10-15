# How to verify an error entry

An entry may be marked `verified_against` only if you reproduced the failure on a real CA and captured the raw output.

1. **Set up a CA** you are allowed to test against (lab: `lab/stepca-up.sh` or `lab/up.sh`, or your own non-production CA).
2. **Reproduce** with a minimal request that triggers the error (a CSR with a short key, a blocked identifier, a bad password...). Prefer a scripted command.
3. **Capture** the exact error text, the CA name and version, the command, and the date.
4. **Add the entry** to `src/pkisage/errors/<ca>.yaml` with `verified_against: <ca>-<version>`.
5. **Add a fixture** row to `tests/data/real_ca_errors.json`: `{"ca": ..., "text": <raw output>, "category": ..., "source": ...}`. `tests/test_pkisage.py::test_real_ca_errors_explained` checks it.
6. **Open a PR** describing the reproduction steps. Redact hostnames, account names and secrets from the captured text.

Do not verify from documentation alone; use `source:` for that (status `documented`).
