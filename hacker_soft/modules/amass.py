from __future__ import annotations

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import run_tool


class AmassModule(ScannerModule):
    name = "amass"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.with_tools:
            result.artifacts["skipped"] = "требуется --with-tools"
            return result

        args = [
            "amass",
            "enum",
            "-passive",
            "-nocolor",
            "-d",
            context.target.domain,
            "-timeout",
            str(max(1, min(4, context.config.timeout_seconds // 2))),
        ]
        timeout = max(90, min(240, context.config.timeout_seconds * 24))
        code, stdout, stderr = run_tool(args, timeout=timeout, logger=context.logger)
        if code == 127:
            result.errors.append("amass не найден")
            return result
        if code != 0 and not stdout:
            result.errors.append(f"amass завершился ошибкой: {stderr.strip()[:500]}")
            return result

        hosts = {
            line.strip().lower().strip(".")
            for line in stdout.splitlines()
            if is_owned_host(line.strip(), context.target.domain)
        }
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


def is_owned_host(host: str | None, domain: str) -> bool:
    if not host:
        return False
    host = host.lower().strip().strip(".")
    return host == domain or host.endswith("." + domain)
