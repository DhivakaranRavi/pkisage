#!/usr/bin/env bash
# Live, narrated PKI demonstration. Run from the project root:  ./demo.sh   (or ./demo.sh --quick)
# Needs openssl and the .venv. Part 4-5 use the network (github.com). Uses .env for live Jev/LLM if present.
# PAUSE=0 ./demo.sh  runs without waiting between steps.
set -u
ROOT=$PWD
PAUSE=${PAUSE:-1}
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
mkdir "$D/csrs"; cp "$ROOT"/src/pkisage/profiles/{old,new}.yaml "$D/"
cp "$ROOT/.env" "$D/.env" 2>/dev/null || true
cd "$D" || exit 1
pk()   { "$ROOT/.venv/bin/pkisage" "$@"; }
B=$'\033[1m'; C=$'\033[36m'; N=$'\033[0m'
say()  { printf "\n${B}${C}== %s${N}\n" "$1"; }
note() { printf "${C}   %s${N}\n" "$1"; }
run()  { printf "${B}\$ pkisage %s${N}\n" "$*"; pk "$@"; sleep "$PAUSE"; }
mk()   { openssl req -new -nodes -keyout /dev/null -subj "/CN=$1.example.com" "${@:2}" -out "csrs/$1.csr" 2>/dev/null; }

mk billing -newkey rsa:2048 -addext subjectAltName=DNS:billing.example.com
mk portal  -newkey rsa:3072
mk api     -newkey rsa:3072 -addext subjectAltName=DNS:api.example.com
printf 'Customer app returns HTTP 400 after cutover. CA says: key length too short\n' > ticket.txt
pk diagnose --ticket ticket.txt --csr csrs/billing.csr --profile new.yaml --json > report.json 2>/dev/null

say "1. CA migration: which customer apps break on the new platform?"
note "Old platform: RSA 2048, SAN optional. New platform: RSA 3072, SAN required (a stricter certificate profile)."
run migrate-check --old old.yaml --new new.yaml --input csrs

say "2. Pre-flight: why billing.csr will be rejected, and the exact fix"
note "Policy checks run before the request ever reaches the CA."
run preflight csrs/billing.csr --profile new.yaml

say "3. Translate the CA's error, then diagnose with evidence"
run explain --ca ejbca --error "key length too short"
run diagnose --ticket ticket.txt --csr csrs/billing.csr --profile new.yaml
note "verified=True only because the deterministic key-size check reproduced it; the AI never decides the facts."

if [ "${1:-}" = "--quick" ]; then
  say "Done (quick mode)"; exit 0
fi

say "4. Real X.509 inspection and the PQC readiness flag"
openssl s_client -connect github.com:443 -servername github.com -showcerts </dev/null 2>/dev/null > raw
"$ROOT/.venv/bin/python" - <<'EOF'
import re
c = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", open("raw").read(), re.S)
open("leaf.pem", "w").write(c[0] + "\n")
open("inter.pem", "w").write(c[1] + "\n")
open("full.pem", "w").write("\n".join(c) + "\n")
EOF
run cert leaf.pem
run preflight leaf.pem --profile new.yaml

say "5. Trust chain and revocation (live: github.com)"
note "Chain: leaf -> intermediate -> a root in the system trust store."
run chain full.pem --ca-bundle /etc/ssl/cert.pem
note "Missing intermediate: the leaf alone cannot be completed to a trusted root."
run chain leaf.pem --ca-bundle /etc/ssl/cert.pem
note "Live OCSP query to the CA's responder:"
run ocsp leaf.pem --issuer inter.pem

say "6. Expiry monitoring (Prometheus text format)"
run metrics leaf.pem

say "7. Log analysis: HSM and Tomcat PKI errors"
printf 'INFO starting\nERROR CKR_PIN_INCORRECT slot 1\njava.lang.Exception: PKIX path building failed\n' > app.log
run log app.log

say "8. AI used carefully: classify, then draft a reply from verified facts"
note "Replies must cite numbered facts; uncited sentences are dropped. A human approves before sending."
run triage --ticket ticket.txt
run reply --from report.json || note "(set PKISAGE_LLM_* in .env to enable the reply draft)"

say "Done. Everything above was read-only: pkisage never changes a CA."
