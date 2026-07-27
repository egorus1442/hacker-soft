from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .logging import ScanLogger


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Target:
    raw: str
    domain: str
    company: str | None = None
    authorized: bool = True


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    explanation: str = ""
    impact: str = ""
    fix: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ModuleResult:
    module: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    profile: str = "standard"
    active: bool = False
    with_tools: bool = False
    heavy_tools: bool = False
    auto_dork_search: bool = False
    max_dork_queries: int = 50
    max_dork_results: int = 50
    timeout_seconds: int = 10
    max_hosts: int = 200
    max_urls_per_host: int = 12
    out_dir: Path = Path("reports")


@dataclass
class ScanContext:
    target: Target
    config: ScanConfig
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    subdomains: set[str] = field(default_factory=set)
    live_hosts: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    open_ports: dict[str, set[int]] = field(default_factory=dict)
    http_services: dict[str, dict[str, Any]] = field(default_factory=dict)
    dns_records: dict[str, Any] = field(default_factory=dict)
    logger: ScanLogger | None = None
