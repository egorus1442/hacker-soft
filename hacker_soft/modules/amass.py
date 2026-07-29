from __future__ import annotations

import re

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

        context.config.out_dir.mkdir(parents=True, exist_ok=True)
        budget_minutes = AMASS_BUDGET_MINUTES
        domain = context.target.domain

        # amass v5 dropped `-o`: `enum` only writes to a local asset graph now, and
        # results have to be pulled back out with a separate `subs` call.
        enum_args = [
            "amass",
            "enum",
            "-passive",
            "-nocolor",
            "-silent",
            "-d",
            domain,
            "-timeout",
            str(budget_minutes),
        ]
        enum_timeout = budget_minutes * 60 + 30
        enum_code, _enum_stdout, enum_stderr = run_tool(enum_args, timeout=enum_timeout, logger=context.logger)
        if enum_code == 127:
            result.errors.append("amass не найден")
            return result

        subs_args = ["amass", "subs", "-names", "-nocolor", "-d", domain]
        subs_code, subs_stdout, subs_stderr = run_tool(subs_args, timeout=60, logger=context.logger)
        if subs_code == 127:
            result.errors.append("amass subs не найден")
            return result

        hosts = collect_amass_hosts(subs_stdout, domain)
        result.artifacts["amass_subs_exit_code"] = subs_code
        if not hosts:
            # Amass prints a progress bar into stderr, so an empty run must not look like a crash.
            result.artifacts["amass_status"] = "failed" if enum_code not in {0, 124} else "no_data"
            sample = strip_progress_noise(enum_stderr)[:300] or strip_progress_noise(subs_stderr)[:300]
            result.artifacts["amass_stderr_sample"] = sample
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


def collect_amass_hosts(stdout: str, domain: str) -> set[str]:
    hosts: set[str] = set()
    for line in stdout.splitlines():
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
