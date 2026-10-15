from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from typing import Any

from pkisage.netutil import open_url


class JiraClient:
    """Minimal Jira Cloud REST v2 client (Basic auth: account email + API token)."""

    def __init__(self, url: str, email: str, token: str, timeout: float = 20.0) -> None:
        self.url, self.timeout = url.rstrip("/"), timeout
        cred = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.headers = {"Authorization": f"Basic {cred}", "Content-Type": "application/json",
                        "Accept": "application/json"}

    @classmethod
    def from_env(cls) -> JiraClient:
        url, email, tok = (os.environ.get(k) for k in
                           ("PKISAGE_JIRA_URL", "PKISAGE_JIRA_EMAIL", "PKISAGE_JIRA_TOKEN"))
        if not (url and email and tok):
            raise ValueError("Set PKISAGE_JIRA_URL, PKISAGE_JIRA_EMAIL and PKISAGE_JIRA_TOKEN")
        return cls(url, email, tok)

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        req = urllib.request.Request(
            f"{self.url}{path}", method=method, headers=self.headers,
            data=json.dumps(body).encode() if body is not None else None)
        try:
            with open_url(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            hint = (
                " (Jira returns 404 for issues you cannot see; check the key, the token's "
                "project access, and that the email owns the token)"
                if e.code in (401, 403, 404)
                else ""
            )
            raise ValueError(
                f"Jira {method} {path.split('?')[0]} failed: HTTP {e.code}{hint}"
            ) from e
        return json.loads(raw) if raw else {}

    def get_ticket_text(self, key: str) -> str:
        d = self._call("GET", f"/rest/api/2/issue/{key}?fields=summary,description")
        f = d["fields"]
        return f"{f.get('summary') or ''}\n\n{f.get('description') or ''}".strip()

    def add_comment(self, key: str, body: str) -> str:
        d = self._call("POST", f"/rest/api/2/issue/{key}/comment", {"body": body})
        return str(d.get("id", ""))

    def create_issue(self, project: str, summary: str, description: str,
                     issue_type: str = "Task") -> str:
        d = self._call("POST", "/rest/api/2/issue", {"fields": {
            "project": {"key": project}, "summary": summary,
            "description": description, "issuetype": {"name": issue_type}}})
        return str(d["key"])

    def get_issue_with_attachments(self, key: str) -> tuple[str, list[dict[str, str]]]:
        d = self._call("GET", f"/rest/api/2/issue/{key}?fields=summary,description,attachment")
        f = d["fields"]
        text = f"{f.get('summary') or ''}\n\n{f.get('description') or ''}".strip()
        atts = [{"filename": a["filename"], "url": a["content"]} for a in f.get("attachment") or []]
        return text, atts

    def download(self, url: str, max_bytes: int = 5_000_000) -> bytes:
        req = urllib.request.Request(url, headers={"Authorization": self.headers["Authorization"]})
        with open_url(req, timeout=self.timeout) as r:
            data: bytes = r.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("attachment too large")
        return data

    def add_label(self, key: str, label: str) -> None:
        self._call("PUT", f"/rest/api/2/issue/{key}", {"update": {"labels": [{"add": label}]}})
