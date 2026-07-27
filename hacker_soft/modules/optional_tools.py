from __future__ import annotations

import json

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import run_tool


class OptionalToolsModule(ScannerModule):
    name = "optional_tools"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.with_tools:
            result.artifacts["skipped"] = "требуется --with-tools"
            return result

        self._subdomain_tools(context, result)
        self._nuclei(context, result)
        return result

    def _subdomain_tools(self, context: ScanContext, result: ModuleResult) -> None:
        domain = context.target.domain
        for tool, args in [
            ("subfinder", ["subfinder", "-silent", "-d", domain]),
            ("assetfinder", ["assetfinder", "--subs-only", domain]),
        ]:
            code, stdout, stderr = run_tool(args, timeout=180, logger=context.logger)
            if code == 127:
                result.errors.append(f"{tool} не найден")
                continue
            if code != 0:
                result.errors.append(f"{tool} завершился ошибкой: {stderr.strip()[:300]}")
                continue
            hosts = {
                line.strip().lower()
                for line in stdout.splitlines()
                if line.strip().lower().endswith("." + domain)
            }
            context.subdomains.update(hosts)
            result.artifacts[f"{tool}_count"] = len(hosts)

    def _nuclei(self, context: ScanContext, result: ModuleResult) -> None:
        urls = sorted(context.live_hosts)
        if not urls:
            return
        code, _, stderr = run_tool(["nuclei", "-version"], timeout=10, logger=context.logger)
        if code == 127:
            result.errors.append("nuclei не найден")
            return
        if code != 0:
            result.errors.append(f"проверка версии nuclei завершилась ошибкой: {stderr.strip()}")
            return

        targets_arg = ",".join(urls[:50])
        args = [
            "nuclei",
            "-u",
            targets_arg,
            "-severity",
            "info,low,medium,high,critical",
            "-jsonl",
            "-silent",
            "-rate-limit",
            "25",
        ]
        code, stdout, stderr = run_tool(args, timeout=600, logger=context.logger)
        if code != 0 and not stdout:
            result.errors.append(f"nuclei завершился ошибкой: {stderr.strip()[:500]}")
            return

        count = 0
        for line in stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            severity = map_severity(info.get("severity"))
            result.findings.append(
                Finding(
                    module=self.name,
                    title=f"Nuclei: {info.get('name') or item.get('template-id')}",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    target=item.get("matched-at") or item.get("host") or context.target.domain,
                    evidence={
                        "template": item.get("template-id"),
                        "type": item.get("type"),
                        "matcher": item.get("matcher-name"),
                        "tags": info.get("tags"),
                    },
                    recommendation="Проверь находку вручную, затем исправь по описанию шаблона и рекомендациям вендора.",
                    references=item.get("template-url") and [item["template-url"]] or [],
                )
            )
            count += 1
        result.artifacts["nuclei_findings"] = count


def map_severity(value: str | None) -> Severity:
    if value == "critical":
        return Severity.CRITICAL
    if value == "high":
        return Severity.HIGH
    if value == "medium":
        return Severity.MEDIUM
    if value == "low":
        return Severity.LOW
    return Severity.INFO
