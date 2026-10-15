from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import TypeAdapter
from rich.table import Table

from pkisage import __version__
from pkisage.adapters.acme import AcmeClient, AcmeError, csr_der, csr_domains
from pkisage.adapters.enroll import SOURCE, check_digicert_order
from pkisage.ai.decision import RuleBasedDecisionModel
from pkisage.ai.evaluate import evaluate_model, verify_lock
from pkisage.ai.providers import ChatProvider, JevDecisionModel, default_decision_model
from pkisage.ai.redact import redact
from pkisage.ai.validate import cited_reply, template_reply, unsupported_in_reply
from pkisage.checks.chain import check_chain
from pkisage.checks.ocsp import check_ocsp
from pkisage.checks.parse import load_any
from pkisage.checks.preflight import evaluate, has_failures, load_profile
from pkisage.core.diagnose import diagnose as run_diagnose
from pkisage.core.explain import explain as run_explain
from pkisage.core.explain import unknown_entry
from pkisage.core.jira_flow import diagnose_ticket
from pkisage.core.migrate import migrate_check as run_migrate
from pkisage.env import load_dotenv
from pkisage.jira import JiraClient
from pkisage.logs.parser import parse_log
from pkisage.models import DiagnosisReport, Finding
from pkisage.report import console, kb_template, print_findings, to_jira

app = typer.Typer(help="pkisage: PKI preflight, diagnosis and migration checks.", no_args_is_help=True)

JsonOpt = Annotated[bool, typer.Option("--json", help="Emit JSON")]


def _emit(findings: list[Finding], as_json: bool, title: str) -> None:
    if as_json:
        typer.echo(TypeAdapter(list[Finding]).dump_json(findings, indent=2).decode())
    else:
        print_findings(findings, title)
    if has_failures(findings):
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(version: Annotated[bool, typer.Option("--version")] = False) -> None:
    load_dotenv()
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command()
def preflight(
    file: Path,
    profile: Annotated[str, typer.Option(help="Profile YAML")] = "corp-web.yaml",
    json_out: JsonOpt = False,
) -> None:
    """Check a CSR (or cert) against a profile before it reaches a CA."""
    _emit(evaluate(load_any(file), load_profile(profile)), json_out, f"preflight {file.name}")


@app.command()
def cert(file: Path, json_out: JsonOpt = False) -> None:
    """Show parsed certificate/CSR fields."""
    obj = load_any(file)
    d = {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in vars(obj).items()}
    d["validity_days"] = obj.validity_days
    d["pq_vulnerable"] = obj.pq_vulnerable
    if json_out:
        typer.echo(json.dumps(d, indent=2, default=str))
        return
    t = Table(title=str(file.name))
    t.add_column("Field")
    t.add_column("Value", overflow="fold")
    for k, v in d.items():
        t.add_row(k, str(v))
    console.print(t)


@app.command()
def chain(
    file: Path,
    ca_bundle: Annotated[Path, typer.Option("--ca-bundle")],
    json_out: JsonOpt = False,
) -> None:
    """Validate the trust path against a CA bundle."""
    _emit(check_chain(file, ca_bundle), json_out, "chain")


@app.command()
def ocsp(
    file: Path,
    issuer: Annotated[Path | None, typer.Option(help="Issuer cert PEM")] = None,
    json_out: JsonOpt = False,
) -> None:
    """Check OCSP/CRL presence and OCSP responder status."""
    _emit(check_ocsp(file, issuer), json_out, "ocsp")


@app.command()
def explain(
    error: Annotated[str, typer.Option("--error")],
    ca: Annotated[str | None, typer.Option("--ca", help="ejbca|digicert|acme")] = None,
    json_out: JsonOpt = False,
) -> None:
    """Translate a raw CA error into cause and fix."""
    try:
        hits = run_explain(error, ca) or [unknown_entry()]
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(2) from e
    if json_out:
        typer.echo(json.dumps([{**h.model_dump(mode="json"), "status": h.status} for h in hits],
                              indent=2))
        return
    for h in hits:
        tag = h.status + (f": {h.verified_against}" if h.verified_against else "")
        console.print(f"[bold]{h.category.value}[/] ({h.id}) \\[{tag}]\n  Cause: {h.cause}\n"
                      f"  Fix: {h.fix}")


@app.command("migrate-check")
def migrate_check(
    old: Annotated[Path, typer.Option("--old")],
    new: Annotated[Path, typer.Option("--new")],
    input_dir: Annotated[Path, typer.Option("--input")],
    json_out: JsonOpt = False,
) -> None:
    """Run a folder of CSRs/certs against old and new profiles."""
    results = run_migrate(input_dir, load_profile(old), load_profile(new))
    if json_out:
        typer.echo(json.dumps([{**r.model_dump(mode="json"), "verdict": r.verdict,
                                "pq_vulnerable": r.pq_vulnerable}
                               for r in results], indent=2))
    else:
        t = Table(title="Migration check")
        for c in ("App", "Old", "New", "Verdict", "PQ-vulnerable", "New failures"):
            t.add_column(c, overflow="fold")
        for r in results:
            fails = "; ".join(f"{f.rule_id}: {f.evidence}" for f in r.new if f.severity.value == "FAIL")
            t.add_row(r.app, "OK" if r.old_ok else "FAIL", "OK" if r.new_ok else "FAIL",
                      r.verdict, "yes" if r.pq_vulnerable else "no", fails)
        console.print(t)
    if any(not r.new_ok for r in results):
        raise typer.Exit(1)


@app.command()
def log(file: Path, json_out: JsonOpt = False) -> None:
    """Match CA/OCSP/Tomcat/HSM log patterns to known issues."""
    matches = parse_log(file)
    if json_out:
        typer.echo(json.dumps([m.model_dump(mode="json") for m in matches], indent=2))
        return
    if not matches:
        console.print("No known patterns matched.")
    for m in matches:
        console.print(f"[bold]{m.category.value}[/] ({m.source}/{m.pattern_id}) line {m.line_no}\n"
                      f"  {m.line}\n  Cause: {m.cause}\n  Fix: {m.fix}")


@app.command()
def triage(ticket: Annotated[Path, typer.Option("--ticket")], json_out: JsonOpt = False) -> None:
    """Classify a ticket (offline rule-based decision layer)."""
    d = default_decision_model().classify(redact(ticket.read_text(errors="replace")))
    if json_out:
        typer.echo(d.model_dump_json(indent=2))
    else:
        console.print(f"{d.category.value} confidence={d.confidence:.2f} route={d.route} "
                      f"refs={d.evidence_refs}")


@app.command()
def diagnose(
    ticket: Annotated[Path | None, typer.Option("--ticket")] = None,
    csr: Annotated[Path | None, typer.Option("--csr")] = None,
    log_file: Annotated[Path | None, typer.Option("--log")] = None,
    profile: str = "corp-web.yaml",
    json_out: JsonOpt = False,
    jira: Annotated[bool, typer.Option("--jira", help="Jira comment markup")] = False,
) -> None:
    """Combine ticket, CSR and log into a root-cause report."""
    if not (ticket or csr or log_file):
        typer.echo("Provide at least one of --ticket, --csr, --log", err=True)
        raise typer.Exit(2)
    r = run_diagnose(ticket, csr, log_file, profile)
    if json_out:
        typer.echo(r.model_dump_json(indent=2))
        return
    if jira:
        typer.echo(to_jira(r))
        return
    console.print(f"[bold]Root cause:[/] {r.root_cause}\n[bold]Category:[/] {r.category.value}\n"
                  f"[bold]Confidence:[/] {r.confidence:.2f}  verified={r.verified}\n"
                  f"[bold]Fix:[/] {r.fix}")
    for e in r.evidence:
        console.print(f"  - {e}", markup=False)


kb_app = typer.Typer(help="Knowledge-base tools")
app.add_typer(kb_app, name="kb")


@kb_app.command("draft")
def kb_draft(
    report: Annotated[Path, typer.Option("--from", help="diagnose --json report")],
    use_llm: Annotated[bool, typer.Option("--llm", help="Polish with the chat model")] = False,
) -> None:
    """Draft a runbook/KB entry from a diagnosis report (human reviews before publishing)."""
    r = DiagnosisReport.model_validate_json(report.read_text())
    base = kb_template(r)
    llm = ChatProvider.from_env() if use_llm else None
    if use_llm and llm is None:
        typer.echo("LLM not configured; emitting template", err=True)
    if llm:
        base = llm.complete("Rewrite this runbook draft in clear markdown. Add no new facts:\n"
                            + base)
        bad = unsupported_in_reply(base, r.model_dump_json())
        if bad:
            typer.echo(f"[WARNING: not in source, review: {bad}]", err=True)
    typer.echo(base)


jira_app = typer.Typer(help="Jira Cloud integration")
app.add_typer(jira_app, name="jira")


@jira_app.command("triage")
def jira_triage(key: str, json_out: JsonOpt = False) -> None:
    """Fetch a Jira ticket (read-only) and classify it."""
    text = JiraClient.from_env().get_ticket_text(key)
    d = default_decision_model().classify(redact(text))
    if json_out:
        typer.echo(d.model_dump_json(indent=2))
    else:
        console.print(f"{key}: {d.category.value} confidence={d.confidence:.2f} route={d.route}")


@jira_app.command("comment")
def jira_comment(
    key: str,
    report: Annotated[Path, typer.Option("--from", help="diagnose --json report")],
    yes: Annotated[bool, typer.Option("--post", "--yes", help="Actually post (default: preview)")] = False,
) -> None:
    """Post a diagnosis as a Jira comment. Previews unless --yes is given."""
    body = to_jira(DiagnosisReport.model_validate_json(report.read_text()))
    if not yes:
        typer.echo(f"[preview - not posted; add --post to post to {key}]\n{body}")
        return
    cid = JiraClient.from_env().add_comment(key, body)
    typer.echo(f"Posted comment {cid} on {key}")


@jira_app.command("diagnose")
def jira_diagnose(
    key: str,
    apply: Annotated[bool, typer.Option("--post", "--apply", help="Add label + comment to the ticket")] = False,
    reply_draft: Annotated[bool, typer.Option("--reply", help="Also draft a customer reply")] = False,
    profile: str = "corp-web.yaml",
    json_out: JsonOpt = False,
) -> None:
    """Full pipeline on a ticket: attachments -> checks -> Jev -> diagnosis (-> reply draft)."""
    client = JiraClient.from_env()
    res = diagnose_ticket(client, key, profile)
    if json_out:
        typer.echo(res.model_dump_json(indent=2))
    else:
        t, r = res.triage, res.report
        console.print(f"[bold]{key}[/] triage: {t.category.value} conf={t.confidence:.2f} "
                      f"route={t.route}\nattachments used: {res.attachments_used or 'none'}\n"
                      f"[bold]Diagnosis:[/] {r.category.value} verified={r.verified} "
                      f"conf={r.confidence:.2f}\n{r.root_cause}\nFix: {r.fix}\nlabel: {res.label}")
        for e in r.evidence:
            console.print(f"  - {e}", markup=False)
    if reply_draft:
        llm = ChatProvider.from_env()
        if llm is None:
            typer.echo("LLM not configured; skipping reply draft", err=True)
        else:
            text, dropped, cited = cited_reply(llm, res.report)
            if cited and not text.strip():
                text = template_reply(res.report)
            typer.echo("\n--- reply draft (NOT posted; human approval required) ---\n" + text)
            if dropped:
                typer.echo(f"[dropped {len(dropped)} uncited/unsupported sentence(s)]", err=True)
            if not cited:
                typer.echo("[WARNING: model ignored citation format; review manually]", err=True)
    if not apply:
        typer.echo(f"[dry run: nothing changed in Jira; add --post to label/comment {key}]")
        return
    body = to_jira(res.report) + (
        f"\n_Triage: {res.triage.category.value} ({res.triage.confidence:.2f}, "
        f"route {res.triage.route}). Generated by pkisage; review before acting._")
    client.add_label(key, res.label)
    cid = client.add_comment(key, body)
    typer.echo(f"Applied label '{res.label}' and posted comment {cid} on {key}")


@jira_app.command("create")
def jira_create(
    project: Annotated[str, typer.Option("--project")],
    report: Annotated[Path, typer.Option("--from", help="diagnose --json report")],
    issue_type: Annotated[str, typer.Option("--type")] = "Task",
) -> None:
    """Create a Jira ticket from a diagnosis report."""
    r = DiagnosisReport.model_validate_json(report.read_text())
    key = JiraClient.from_env().create_issue(
        project, f"[pkisage] {r.category.value}: {r.root_cause}"[:250], to_jira(r), issue_type)
    typer.echo(f"Created {key}")


@app.command("acme-probe")
def acme_probe(
    csr: Path,
    directory: Annotated[str, typer.Option("--directory", help="ACME directory URL (lab/test CA)")],
    insecure: Annotated[bool, typer.Option("--insecure", help="Skip TLS verify (lab only)")] = False,
    profile: str = "corp-web.yaml",
    json_out: JsonOpt = False,
) -> None:
    """Submit a CSR to a (lab/test) ACME CA and compare the real answer with preflight."""
    data = csr.read_bytes()
    predicted = [f.rule_id for f in evaluate(load_any(csr), load_profile(profile))
                 if f.severity.value == "FAIL"]
    client = AcmeClient(directory, insecure=insecure)
    out: dict[str, object] = {"preflight_predicts_fail": predicted}
    try:
        order = client.submit_csr(csr_domains(data), csr_der(data))
        out.update(ca_result="accepted", order_status=order.get("status"))
    except AcmeError as e:
        raw = json.dumps(e.body)
        hits = run_explain(raw, "acme")
        out.update(ca_result="rejected", http=e.status, ca_error=e.body,
                   explained=[h.category.value for h in hits])
    out["agreement"] = bool(predicted) == (out["ca_result"] == "rejected")
    if json_out:
        typer.echo(json.dumps(out, indent=2))
    else:
        console.print_json(json.dumps(out))


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the REST API (pip install 'pkisage[api]')."""
    try:
        import uvicorn
    except ImportError as e:
        typer.echo("Install the API extra: pip install 'pkisage[api]'", err=True)
        raise typer.Exit(2) from e
    uvicorn.run("pkisage.api:app", host=host, port=port)


@app.command()
def metrics(
    paths: Annotated[list[Path], typer.Argument(help="Cert files or directories")],
    serve_port: Annotated[int | None, typer.Option("--serve", help="Serve /metrics on this port")] = None,
    host: str = "127.0.0.1",
) -> None:
    """Prometheus-format days-to-expiry for certificates (print once, or --serve /metrics)."""
    from pkisage.metrics import render, serve

    if serve_port is None:
        typer.echo(render(paths), nl=False)
    else:
        serve(paths, host, serve_port)


@app.command("enroll-check")
def enroll_check(
    request: Path,
    profile: Annotated[str, typer.Option(help="Profile YAML")] = "corp-web.yaml",
    json_out: JsonOpt = False,
) -> None:
    """Validate a DigiCert-style order request JSON (shape + embedded CSR) before sending it."""
    body = json.loads(request.read_text())
    if not json_out:
        typer.echo(f"[{SOURCE}]")
    _emit(check_digicert_order(body, load_profile(profile)), json_out, f"enroll-check {request.name}")


@app.command("ai-eval")
def ai_eval(
    dataset: Annotated[Path, typer.Argument(help="JSONL of {text, label}")],
    model: Annotated[str, typer.Option(help="rules|jev")] = "rules",
    heldout: Annotated[bool, typer.Option("--heldout", help="Require an intact .sha256 lock")] = False,
) -> None:
    """Measure decision-model accuracy, calibration and routing on a labeled set."""
    m = JevDecisionModel.from_env() if model == "jev" else RuleBasedDecisionModel()
    if m is None:
        typer.echo("Set PKISAGE_JEV_URL (and PKISAGE_JEV_API_KEY) to evaluate jev", err=True)
        raise typer.Exit(2)
    if heldout:
        verify_lock(dataset)
    typer.echo(evaluate_model(m, dataset).model_dump_json(indent=2))


@app.command()
def reply(report: Annotated[Path, typer.Option("--from")]) -> None:
    """Draft a customer reply from a diagnose --json report (LLM text only; human approves)."""
    llm = ChatProvider.from_env()
    if llm is None:
        typer.echo("Set PKISAGE_LLM_BASE_URL and PKISAGE_LLM_MODEL (optional PKISAGE_LLM_API_KEY)",
                   err=True)
        raise typer.Exit(2)
    rep = DiagnosisReport.model_validate_json(report.read_text())
    text, dropped, cited = cited_reply(llm, rep)
    if cited and not text.strip():
        text = template_reply(rep)
        typer.echo("[model output failed validation; using deterministic template]", err=True)
    typer.echo(text)
    if dropped:
        typer.echo(f"\n[dropped {len(dropped)} uncited/unsupported sentence(s): {dropped}]", err=True)
    if not cited:
        bad = unsupported_in_reply(text, rep.model_dump_json())
        typer.echo(f"\n[WARNING: model ignored citation format; heuristic check only: {bad}]",
                   err=True)
    typer.echo("\n[DRAFT - requires human approval before sending]")


BANNER = r"""
         _    _     _
  _ __  | | _(_)___  __ _  __ _  ___
 | '_ \ | |/ / / __|/ _` |/ _` |/ _ \
 | |_) ||   <| \__ \ (_| | (_| |  __/
 | .__/ |_|\_\_|___/\__,_|\__, |\___|
 |_|                      |___/
   read-only PKI diagnostics, migration checks & ticket triage
"""


def show_banner(argv: list[str]) -> None:
    """Banner only for bare `pkisage` or top-level --help, and only on a terminal."""
    if sys.stdout.isatty() and (not argv or argv in (["--help"], ["-h"])):
        console.print(BANNER, style="bold cyan", markup=False, highlight=False)


def run() -> None:
    show_banner(sys.argv[1:])
    try:
        app()
    except (ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise SystemExit(2) from e
