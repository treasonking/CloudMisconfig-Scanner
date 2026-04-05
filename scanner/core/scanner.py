from __future__ import annotations

from scanner.core.interfaces import Check, CloudProvider, Reporter
from scanner.core.models import ScanResult


class MisconfigScanner:
    def __init__(
        self,
        provider: CloudProvider,
        reporters: list[Reporter] | None = None,
        checks: list[Check] | None = None,
    ):
        self.provider = provider
        self.reporters = reporters or []
        self.checks = checks or []

    def run(self) -> ScanResult:
        result = self.provider.collect()

        if result.ok:
            for check in self.checks:
                result.findings.extend(check.evaluate(result))

        for reporter in self.reporters:
            print(reporter.render(result))

        return result
