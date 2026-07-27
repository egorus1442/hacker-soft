from __future__ import annotations

import re
from pathlib import Path

from hacker_soft.core.models import Category, Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import run_tool


AMASS_BUDGET_MINUTES = 2
PROGRESS_NOISE_RE = re.compile(r"\d+\s*/\s*\d+\s*\[[^\]]*\]\s*\d+(?:\.\d+)?%\s*\??\s*p/s")


class AmassModule(ScannerModule):
    name = "amass"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.with_tools:
            result.artifacts["skipped"] = "требуется --with-tools"
            return result

        output_file = context.config.out_dir / "amass-hosts.txt"
        context.config.out_dir.mkdir(parents=True, exist_ok=True)
        budget_minutes = AMASS_BUDGET_MINUTES
        args = [
            "amass",
            "enum",
            "-passive",
            "-nocolor",
            "-silent",
            "-d",
            context.target.domain,
            "-o",
            str(output_file),
            "-timeout",
            str(budget_minutes),
        ]
        timeout = budget_minutes * 60 + 30
        code, stdout, stderr = run_tool(args, timeout=timeout, logger=context.logger)
        if code == 127:
            result.errors.append("amass не найден")
            return result

        hosts = collect_amass_hosts(stdout, output_file, context.target.domain)
        result.artifacts["amass_output"] = {
            "path": str(output_file),
            "exists": output_file.exists(),
            "bytes": output_file.stat().st_size if output_file.exists() else 0,
        }
        if not hosts:
            # Amass prints a progress bar into stderr, so an empty run must not look like a crash.
            result.artifacts["amass_status"] = "failed" if code not in {0, 124} else "no_data"
            result.artifacts["amass_stderr_sample"] = strip_progress_noise(stderr)[:300]
            return result
        before = len(context.subdomains)
        context.subdomains.update(hosts)
        added = len(context.subdomains) - before
        result.artifacts["amass_hosts"] = len(hosts)
        result.artifacts["amass_added"] = added

        if added:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Amass нашел дополнительные поддомены",
                    severity=Severity.INFO,
                    category=Category.INVENTORY,
                    confidence=Confidence.HIGH,
                    target=context.target.domain,
                    evidence={"added": added, "sample": sorted(hosts)[:25]},
                    recommendation="Сверь найденные Amass активы с инвентарем и владельцами систем.",
                    explanation="Amass нашел дополнительные поддомены в публичных источниках.",
                    impact="Неучтенные поддомены могут означать забытые сервисы или активы без владельца.",
                    fix="Добавить найденные активы в инвентарь, назначить владельцев и закрыть неиспользуемое.",
                )
            )
        return result


def collect_amass_hosts(stdout: str, output_file: Path, domain: str) -> set[str]:
    text = stdout
    if output_file.exists():
        try:
            text += "\n" + output_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    hosts: set[str] = set()
    for line in text.splitlines():
        candidate = line.strip().split()[0] if line.strip() else ""
        if is_owned_host(candidate, domain):
            hosts.add(candidate.lower().strip("."))
    return hosts


def strip_progress_noise(value: str) -> str:
    return PROGRESS_NOISE_RE.sub("", value or "").strip()


def is_owned_host(host: str | None, domain: str) -> bool:
    if not host:
        return False
    host = host.lower().strip().strip(".")
    return host == domain or host.endswith("." + domain)
