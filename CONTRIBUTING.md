# Contributing

Thanks for helping. The most valuable contributions are **verified CA error entries**.

## Setup
```
python3 -m venv .venv && .venv/bin/pip install -e '.[api]' pytest ruff mypy types-PyYAML httpx
.venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q
```

## Good first issues
- **Add an error entry:** see [docs/error-entries.md](docs/error-entries.md) and [docs/verifying-entries.md](docs/verifying-entries.md).
- **Add a preflight rule:** one rule in `checks/preflight.py` plus one test using a generated CSR/cert.
- **Add a profile:** a YAML in `src/pkisage/profiles/` (see [docs/profiles.md](docs/profiles.md)).
- **Add a log pattern:** `logs/parser.py`, with a test line.

## Rules
- Never mark an entry `verified_against` without a reproduction (CA version, command, captured output, date) and a fixture in `tests/data/real_ca_errors.json`.
- Do not commit real customer data, certificates, keys, tickets or secrets. Use generated fixtures.
- Keep the tool read-only against CAs. New adapters must not add write paths.
- Do not tune classifier thresholds on the held-out set (see [docs/eval.md](docs/eval.md)).
- `ruff`, `mypy --strict` and `pytest` must pass.
