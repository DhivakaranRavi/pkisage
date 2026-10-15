from __future__ import annotations

from pathlib import Path

from conftest import make_csr
from cryptography.hazmat.primitives import hashes
from typer.testing import CliRunner

from pkisage.ai.decision import RuleBasedDecisionModel
from pkisage.ai.redact import redact
from pkisage.checks.chain import check_chain
from pkisage.checks.parse import load_any
from pkisage.checks.preflight import evaluate, load_profile
from pkisage.cli import app
from pkisage.core.explain import explain
from pkisage.core.migrate import migrate_check
from pkisage.logs.parser import parse_log
from pkisage.models import ErrorCategory, Severity

runner = CliRunner()


def failed(findings: list, rule: str) -> bool:  # type: ignore[type-arg]
    return any(f.rule_id == rule and f.severity == Severity.FAIL for f in findings)


def test_good_csr_passes(tmp_path: Path) -> None:
    f = evaluate(load_any(make_csr(tmp_path / "a.csr")), load_profile("corp-web.yaml"))
    assert not any(x.severity == Severity.FAIL for x in f)


def test_weak_key(tmp_path: Path) -> None:
    f = evaluate(load_any(make_csr(tmp_path / "a.csr", bits=1024)), load_profile("corp-web.yaml"))
    assert failed(f, "key-size")


def test_missing_san(tmp_path: Path) -> None:
    f = evaluate(load_any(make_csr(tmp_path / "a.csr", san=False)), load_profile("corp-web.yaml"))
    assert failed(f, "san-present")


def test_eku(tmp_path: Path) -> None:
    f = evaluate(load_any(make_csr(tmp_path / "a.csr", eku=True)), load_profile("corp-web.yaml"))
    assert failed(f, "eku-allowed")


def test_sig_alg(tmp_path: Path) -> None:
    prof = load_profile("corp-web.yaml").model_copy(update={"allowed_sig_algs": ["sha512"]})
    f = evaluate(load_any(make_csr(tmp_path / "a.csr", h=hashes.SHA256())), prof)
    assert failed(f, "sig-alg")


def test_ec_key_ok(tmp_path: Path) -> None:
    f = evaluate(load_any(make_csr(tmp_path / "a.csr", ec_key=True)), load_profile("corp-web.yaml"))
    assert not any(x.severity == Severity.FAIL for x in f)


def test_validity_and_expiry(pki: dict[str, Path]) -> None:
    prof = load_profile("corp-web.yaml").model_copy(update={"max_validity_days": 30})
    assert failed(evaluate(load_any(pki["leaf"]), prof), "validity")


def test_migrate(tmp_path: Path) -> None:
    make_csr(tmp_path / "ok.csr")
    make_csr(tmp_path / "weak.csr", bits=2048, san=False)
    res = {r.app: r.verdict for r in migrate_check(
        tmp_path, load_profile("old.yaml"), load_profile("new.yaml"))}
    assert res == {"ok": "OK", "weak": "BREAKS"}


def test_chain(pki: dict[str, Path]) -> None:
    assert check_chain(pki["full"], pki["bundle"])[0].severity == Severity.PASS
    bad = check_chain(pki["leaf"], pki["bundle"])[0]
    assert bad.category == ErrorCategory.CHAIN_UNTRUSTED


def test_explain() -> None:
    assert explain("Subject Alternative Name is required", "ejbca")[0].category == (
        ErrorCategory.SAN_MISSING)
    assert explain("type urn:ietf:params:acme:error:badCSR", "acme")


def test_log(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    p.write_text("ok\nERROR CKR_PIN_INCORRECT on slot 1\n")
    m = parse_log(p)
    assert m[0].line_no == 2 and m[0].category == ErrorCategory.AUTH_FAILED


def test_redact() -> None:
    out = redact("password=hunter2 mail bob@corp.com Bearer abc.def")
    assert "hunter2" not in out and "bob@corp.com" not in out and "abc.def" not in out


def test_decision_unknown_human() -> None:
    d = RuleBasedDecisionModel().classify("gibberish")
    assert d.route == "human"


def test_cli(tmp_path: Path) -> None:
    csr = make_csr(tmp_path / "w.csr", bits=1024)
    r = runner.invoke(app, ["preflight", str(csr)])
    assert r.exit_code == 1
    r = runner.invoke(app, ["explain", "--ca", "ejbca", "--error", "key length too short"])
    assert r.exit_code == 0 and "KEY_TOO_WEAK" in r.output
    r = runner.invoke(app, ["diagnose", "--csr", str(csr), "--json"])
    assert '"verified": true' in r.output
    r = runner.invoke(app, ["migrate-check", "--old", "old.yaml", "--new", "new.yaml",
                            "--input", str(tmp_path)])
    assert "Migration" in r.output


def test_real_ca_errors_explained() -> None:
    import json

    rows = json.loads((Path(__file__).parent / "data" / "real_ca_errors.json").read_text())
    for r in rows:
        cats = {e.category.value for e in explain(r["text"], r["ca"])}
        assert cats == {r["category"]} or r["category"] in cats, r["text"]
        assert r["category"] != "UNKNOWN" or cats


def test_ip_only_san_fails(tmp_path: Path) -> None:
    import subprocess

    p = tmp_path / "ip.csr"
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-keyout", "/dev/null",
                    "-subj", "/CN=x", "-addext", "subjectAltName=IP:10.0.0.1", "-out", str(p)],
                   check=True, capture_output=True)
    assert failed(evaluate(load_any(p), load_profile("corp-web.yaml")), "san-dns")
