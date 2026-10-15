from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from pkisage.jira import JiraClient

SEEN: list[tuple[str, str, str]] = []


class H(BaseHTTPRequestHandler):
    def _send(self, obj: object) -> None:
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        SEEN.append(("GET", self.path, self.headers["Authorization"] or ""))
        self._send({"fields": {"summary": "HTTP 400", "description": "key length too short"}})

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        SEEN.append(("POST", self.path, body))
        self._send({"id": "42"})

    def log_message(self, *a: object) -> None:
        pass


@pytest.fixture
def jira() -> Iterator[JiraClient]:
    s = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield JiraClient(f"http://127.0.0.1:{s.server_port}", "a@b.com", "tok")
    s.shutdown()


def test_get_and_comment(jira: JiraClient) -> None:
    SEEN.clear()
    assert "key length too short" in jira.get_ticket_text("PKI-1")
    assert SEEN[0][2] == "Basic " + base64.b64encode(b"a@b.com:tok").decode()
    assert jira.add_comment("PKI-1", "hello") == "42"
    assert SEEN[1][1] == "/rest/api/2/issue/PKI-1/comment"


def test_missing_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PKISAGE_JIRA_EMAIL", raising=False)
    with pytest.raises(ValueError):
        JiraClient.from_env()


def test_diagnose_ticket_pipeline(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from pkisage.core.jira_flow import diagnose_ticket

    csr = subprocess.run(
        ["openssl", "req", "-new", "-newkey", "rsa:1024", "-nodes", "-keyout", "/dev/null",
         "-subj", "/CN=a.example.com"], capture_output=True, check=True).stdout

    class Fake(JiraClient):
        def get_issue_with_attachments(self, key: str) -> tuple[str, list[dict[str, str]]]:
            return "key length too short", [
                {"filename": "../evil.csr", "url": "csr"}, {"filename": "x.exe", "url": "bad"}]

        def download(self, url: str, max_bytes: int = 0) -> bytes:
            assert url == "csr"
            return csr

    monkeypatch.delenv("PKISAGE_JEV_URL", raising=False)
    res = diagnose_ticket(Fake("http://x", "a@b.c", "t"), "K-1")
    assert res.report.verified and res.label == "pkisage-key_too_weak"
    assert res.attachments_used == {"csr/cert": "evil.csr"}
