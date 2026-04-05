from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ScanContext:
    provider: str
    region: str
    profile: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    resource: str
    message: str
    recommendation: str | None = None


@dataclass
class ScanResult:
    context: ScanContext
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    @property
    def has_failures(self) -> bool:
        return any(f.status == "FAIL" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": {
                "provider": self.context.provider,
                "region": self.context.region,
                "profile": self.context.profile,
                "started_at": self.context.started_at.isoformat(),
            },
            "errors": self.errors,
            "findings": [asdict(finding) for finding in self.findings],
            "data": self.data,
        }
