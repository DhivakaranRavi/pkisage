from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from pkisage.ai.decision import RuleBasedDecisionModel
from pkisage.ai.evaluate import evaluate_model
from pkisage.ai.providers import ChatProvider, JevDecisionModel

DATA = Path(__file__).parent / "data" / "labeled.jsonl"
SEEN: list[dict[str, object]] = []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append(body)
        if self.path.endswith("/chat/completions"):
            out = {"choices": [{"message": {"content": "draft reply"}}]}
        elif self.path == "/jev":
            out = {"answers": {"category": {"choice": "SAN_MISSING", "confidence": 0.95}}}
        else:
            self.send_response(500)
            self.end_headers()
            return
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[str]:
    s = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


def test_chat_redacts(server: str) -> None:
    SEEN.clear()
    assert ChatProvider(server, "m").complete("password=hunter2 fix it") == "draft reply"
    assert "hunter2" not in json.dumps(SEEN[0])


def test_jev_and_fallback(server: str) -> None:
    d = JevDecisionModel(f"{server}/jev").classify("anything")
    assert d.category.value == "SAN_MISSING" and d.route == "suggested"  # auto-route is opt-in
    fb = JevDecisionModel(f"{server}/broken").classify("key length too short")
    assert fb.category.value == "KEY_TOO_WEAK"


def test_rules_baseline_eval() -> None:
    r = evaluate_model(RuleBasedDecisionModel(), DATA)
    assert r.total == 56 and r.accuracy >= 0.8


def test_reply_validator() -> None:
    from pkisage.ai.validate import unsupported_in_reply

    assert unsupported_in_reply("Use `openssl x` at 3072 bits", "openssl x 3072") == []
    assert unsupported_in_reply("```md\nfoo 1024\n```", "foo 1024") == []
    assert "9999" in unsupported_in_reply("9999 bits", "1024")


def test_auto_route_is_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkisage.ai.provider import route
    from pkisage.models import Decision, ErrorCategory

    d = route(Decision(category=ErrorCategory.KEY_TOO_WEAK, confidence=0.95))
    assert d.route == "suggested"
    monkeypatch.setenv("PKISAGE_TRUST_AUTO", "1")
    assert route(Decision(category=ErrorCategory.KEY_TOO_WEAK, confidence=0.95)).route == "auto"
    assert route(Decision(category=ErrorCategory.KEY_TOO_WEAK, confidence=0.3)).route == "human"
