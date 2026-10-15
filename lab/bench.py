"""Compare pkisage preflight with a real CA (step-ca in podman). Run: .venv/bin/python lab/bench.py"""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from pkisage.checks.parse import load_any
from pkisage.checks.preflight import evaluate, load_profile
from pkisage.core.explain import explain
from pkisage.models import Severity

C = "pkisage-step-ca"
SAN = "-addext subjectAltName=DNS:t.example.com"
VARIANTS = {
    "rsa1024+san": f"-newkey rsa:1024 {SAN}",
    "rsa2048+san": f"-newkey rsa:2048 {SAN}",
    "rsa3072+san": f"-newkey rsa:3072 {SAN}",
    "rsa3072-nosan": "-newkey rsa:3072",
    "ec-p256+san": f"-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 {SAN}",
    "ec-p384+san": f"-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 {SAN}",
    "ec-p521+san": f"-newkey ec -pkeyopt ec_paramgen_curve:secp521r1 {SAN}",
    "rsa3072-sha512": f"-newkey rsa:3072 -sha512 {SAN}",
    "rsa3072-sha1": f"-newkey rsa:3072 -sha1 {SAN}",
    "rsa3072-clientauth-eku": f"-newkey rsa:3072 {SAN} -addext extendedKeyUsage=clientAuth",
    "rsa3072-ip-only-san": "-newkey rsa:3072 -addext subjectAltName=IP:10.0.0.1",
    "ed25519+san": f"-newkey ed25519 {SAN}",
}


def sh(cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, shell=True, capture_output=True, text=True)


def main() -> None:
    prof = load_profile("corp-web.yaml")
    rows = []
    with tempfile.TemporaryDirectory() as d:
        sh(f"podman exec {C} sh -c 'echo lab-only-password > /tmp/pw; mkdir -p /tmp/b'")
        for name, args in VARIANTS.items():
            f = Path(d) / f"{name}.csr"
            r = sh(f"openssl req -new -nodes -keyout /dev/null -subj /CN=t.example.com {args} -out {f}")
            if r.returncode:
                rows.append({"variant": name, "skipped": r.stderr.strip()[:80]})
                continue
            t0 = time.perf_counter()
            try:
                fails = [x.rule_id for x in evaluate(load_any(f), prof) if x.severity == Severity.FAIL]
            except Exception as e:
                fails = [f"parse-error:{e}"]
            pf_ms = (time.perf_counter() - t0) * 1000
            sh(f"podman cp {f} {C}:/tmp/b/{name}.csr")
            s = sh(f"podman exec {C} step ca sign /tmp/b/{name}.csr /tmp/b/{name}.crt "
                   "--provisioner admin --provisioner-password-file /tmp/pw "
                   "--ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt --force")
            err = (s.stdout + s.stderr).strip().splitlines()
            rejected = s.returncode != 0
            msg = next((x for x in err if "forbidden" in x or "error" in x.lower()
                        or "failed" in x.lower()), err[-1] if err else "")
            cats = [e.category.value for e in explain(msg, "stepca")] if rejected else []
            rows.append({"variant": name, "ca_rejected": rejected, "ca_message": msg[:120],
                         "explained": cats, "preflight_fail_rules": fails,
                         "preflight_ms": round(pf_ms, 1)})
    done = [r for r in rows if "ca_rejected" in r]
    rej = [r for r in done if r["ca_rejected"]]
    caught = [r for r in rej if r["preflight_fail_rules"]]
    stricter = [r for r in done if not r["ca_rejected"] and r["preflight_fail_rules"]]
    summary = {"variants": len(done), "ca_rejected": len(rej),
               "ca_rejected_caught_by_preflight": len(caught),
               "catch_rate": round(len(caught) / len(rej), 3) if rej else None,
               "accepted_by_ca_but_flagged_by_policy": len(stricter),
               "mean_preflight_ms": round(sum(r["preflight_ms"] for r in done) / len(done), 1)}
    print(json.dumps({"summary": summary, "rows": rows}, indent=1))


if __name__ == "__main__":
    main()
