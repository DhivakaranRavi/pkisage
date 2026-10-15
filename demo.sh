#!/usr/bin/env bash
# One-minute story: a customer's CSR worked on the old CA and fails after cutover.
# Run from the project root: ./demo.sh   (uses .env for live Jev/LLM if present)
set -u
P=.venv/bin/pkisage; D=$(mktemp -d); trap 'rm -rf "$D"' EXIT; mkdir "$D/csrs"
mk() { openssl req -new -nodes -keyout /dev/null -subj "/CN=$1.example.com" "${@:2}" -out "$D/csrs/$1.csr" 2>/dev/null; }
mk billing -newkey rsa:2048 -addext subjectAltName=DNS:billing.example.com
mk portal  -newkey rsa:3072
mk api     -newkey rsa:3072 -addext subjectAltName=DNS:api.example.com
printf 'Customer app returns HTTP 400 after cutover. CA says: key length too short\n' > "$D/ticket.txt"
echo "### 1. migrate-check: which apps break on the new platform?"
$P migrate-check --old src/pkisage/profiles/old.yaml --new src/pkisage/profiles/new.yaml --input "$D/csrs"
echo; echo "### 2. preflight: why, and how to fix"; $P preflight "$D/csrs/billing.csr" --profile src/pkisage/profiles/new.yaml
echo; echo "### 3. explain the CA error"; $P explain --ca ejbca --error "key length too short"
echo; echo "### 4. diagnose: root cause, evidence, fix, confidence"
$P diagnose --ticket "$D/ticket.txt" --csr "$D/csrs/billing.csr" --profile src/pkisage/profiles/new.yaml --json | tee "$D/report.json"
echo; echo "### 5. reply: LLM draft from verified facts only (human approves)"
$P reply --from "$D/report.json" || echo "(set PKISAGE_LLM_* in .env to enable)"
