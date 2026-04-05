from __future__ import annotations

from typing import Protocol

from scanner.core.models import Finding, ScanResult


class CloudProvider(Protocol):
    name: str

    def collect(self) -> ScanResult:
        ...


class Reporter(Protocol):
    def render(self, result: ScanResult) -> str:
        ...


class Check(Protocol):
    check_id: str

    def evaluate(self, result: ScanResult) -> list[Finding]:
        ...
