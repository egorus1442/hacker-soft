from __future__ import annotations

import urllib.parse
import time

from hacker_soft.core.models import Category, Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import fetch_json


class UrlscanModule(ScannerModule):
    name = "urlscan"
    passive = True

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        domain = context.target.domain
        query = urllib.parse.urlencode({"q": f"domain:{domain}", "size": "100"})
        url = f"https://urlscan.io/api/v1/search/?{query}"
        try:
            started = time.monotonic()
            if context.logger:
                context.logger.info(f"external request start: urlscan domain={domain} timeout=20s")
            data = fetch_json(url, timeout=20)
            if context.logger:
                count = len(data.get("results", [])) if isinstance(data, dict) else "unknown"
                context.logger.info(
                    f"external request end: urlscan domain={domain} elapsed={time.monotonic() - started:.1f}s rows={count}"
                )
        except Exception as exc:  # noqa: BLE001
            if context.logger:
                context.logger.error(
                    f"external request failed: urlscan domain={domain} elapsed={time.monotonic() - started:.1f}s error={exc}"
                )
            result.errors.append(f"запрос к urlscan.io завершился ошибкой: {exc}")
            return result

        entries = data.get("results", []) if isinstance(data, dict) else []
        urls = []
        for item in entries:
            page = item.get("page") or {}
            page_url = page.get("url")
            domain_name = page.get("domain")
            if domain_name and (domain_name == domain or domain_name.endswith("." + domain)):
                context.subdomains.add(domain_name)
                if page_url:
                    urls.append(page_url)

        result.artifacts["url_count"] = len(urls)
        result.artifacts["sample_urls"] = urls[:25]
        if urls:
            result.findings.append(
                Finding(
                module=self.name,
                title="Найдены публичные записи urlscan.io",
                    severity=Severity.INFO,
                    category=Category.INVENTORY,
                    confidence=Confidence.HIGH,
                    target=domain,
                    evidence={"count": len(urls), "sample": urls[:10]},
                    recommendation="Проверь публичные записи на неожиданные хосты, чувствительные URL и сторонние зависимости.",
                    explanation="urlscan.io содержит публичные записи сканирования, связанные с доменом.",
                    impact="В них могут быть видны неожиданные URL, сторонние зависимости или следы старых сервисов.",
                    fix="Проверить записи и убедиться, что там нет чувствительных URL или неожиданных активов.",
                )
            )
        return result
