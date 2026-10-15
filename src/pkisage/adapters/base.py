from __future__ import annotations

from typing import Protocol


class CAAdapter(Protocol):
    """Read-only CA adapter interface."""

    name: str

    def get_request_status(self, request_id: str) -> dict[str, str]: ...


class StubAdapter:
    def __init__(self, name: str) -> None:
        self.name = name

    def get_request_status(self, request_id: str) -> dict[str, str]:
        raise NotImplementedError(f"{self.name} adapter is a stub; no CA calls are made")
