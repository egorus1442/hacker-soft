from __future__ import annotations

import time
import urllib.parse

from hacker_soft.core.logging import ScanLogger
from hacker_soft.core.models import Category, Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import fetch_json, resolve_host


class CertificateTransparencyModule(ScannerModule):
    name = "ct_subdomains"
    passive = True

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        domain = context.target.domain
        names: set[str] = set()
        source_errors: dict[str, str] = {}
        source_counts: dict[str, int] = {}

        for source_name, fetcher in [
            ("crt.sh", fetch_crtsh_names),
            ("certspotter", fetch_certspotter_names),
        ]:
            try:
                source_names = fetcher(domain, context.logger)
            except Exception as exc:  # noqa: BLE001
                source_errors[source_name] = str(exc)
                if context.logger:
                    context.logger.error(f"ct source failed: {source_name} domain={domain} error={exc}")
                continue
            source_counts[source_name] = len(source_names)
            names.update(source_names)

        context.subdomains.update(names)
        result.artifacts["count"] = len(names)
        result.artifacts["source_counts"] = source_counts
        if source_errors:
            result.artifacts["source_errors"] = source_errors

        if not names and source_errors:
            result.errors.append("все CT-источники завершились ошибкой: " + "; ".join(f"{k}: {v}" for k, v in source_errors.items()))
            return result

        if source_errors:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Часть Certificate Transparency источников недоступна",
                    severity=Severity.INFO,
                    category=Category.DIAGNOSTIC,
                    confidence=Confidence.HIGH,
                    target=domain,
                    evidence={"source_errors": source_errors, "source_counts": source_counts},
                    recommendation="Это не уязвимость. Повтори анализ позже или смотри найденные поддомены из оставшихся источников.",
                    explanation="Один из внешних сервисов Certificate Transparency не ответил вовремя, но модуль использовал другие источники.",
                    impact="Отчет может пропустить часть исторических поддоменов, если они были только в недоступном источнике.",
                    fix="Повторить анализ позже; для критичных доменов дополнительно сверить данные через subfinder/amass.",
                )
            )

        if len(names) > 100:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Большая внешняя зона поддоменов",
                    severity=Severity.INFO,
                    category=Category.INVENTORY,
                    confidence=Confidence.HIGH,
                    target=domain,
                    evidence={"subdomain_count": len(names), "source_counts": source_counts},
                    recommendation="Проверь найденные поддомены, убери устаревшие DNS-записи и назначь владельцев активов.",
                    explanation="У домена найдено много поддоменов в публичных источниках.",
                    impact="Чем больше внешних активов, тем выше шанс забытых сервисов, тестовых окружений и неучтенных владельцев.",
                    fix="Сверить поддомены с внутренним инвентарем и убрать все, что больше не используется.",
                )
            )

        unresolved = []
        for host in sorted(names)[: context.config.max_hosts]:
            if not resolve_host(host):
                unresolved.append(host)
        if unresolved:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="В Certificate Transparency есть неразрешающиеся хосты",
                    severity=Severity.INFO,
                    category=Category.INVENTORY,
                    confidence=Confidence.MEDIUM,
                    target=domain,
                    evidence={"sample": unresolved[:25], "count": len(unresolved)},
                    recommendation="Проверь, не указывают ли старые сертификаты или DNS-записи на заброшенные активы.",
                    explanation="В публичных журналах сертификатов есть поддомены, которые сейчас не резолвятся.",
                    impact="Это может быть нормальным следом старой инфраструктуры, но иногда указывает на забытые или мигрированные сервисы.",
                    fix="Проверить список, удалить старые записи и убедиться, что нет риска subdomain takeover.",
                )
            )
        return result


def fetch_crtsh_names(domain: str, logger: ScanLogger | None) -> set[str]:
    names: set[str] = set()
    last_error: Exception | None = None
    variants = [
        ("crt.sh all", {"q": f"%.{domain}", "output": "json"}),
        ("crt.sh unexpired", {"q": f"%.{domain}", "output": "json", "exclude": "expired"}),
    ]
    for source_label, params in variants:
        url = "https://crt.sh/?" + urllib.parse.urlencode(params)
        try:
            rows = fetch_with_log(source_label, domain, url, timeout=8, logger=logger, attempts=2)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
        for row in rows if isinstance(rows, list) else []:
            value = str(row.get("name_value", ""))
            for item in value.splitlines():
                add_owned_name(names, item, domain)
        if names:
            return names
    if last_error:
        raise RuntimeError(str(last_error))
    return names


def fetch_certspotter_names(domain: str, logger: ScanLogger | None) -> set[str]:
    names: set[str] = set()
    after: str | None = None
    for page in range(3):
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        if after:
            params["after"] = after
        url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(params)
        rows = fetch_with_log("certspotter", domain, url, timeout=10, logger=logger, attempts=1, page=page + 1)
        if not isinstance(rows, list) or not rows:
            break
        for row in rows:
            after = str(row.get("id") or after or "")
            for item in row.get("dns_names") or []:
                add_owned_name(names, item, domain)
        if len(rows) < 100:
            break
    return names


def fetch_with_log(
    source: str,
    domain: str,
    url: str,
    timeout: int,
    logger: ScanLogger | None,
    attempts: int,
    page: int | None = None,
):
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        started = time.monotonic()
        label = f"{source} page={page}" if page else source
        if logger:
            logger.info(f"external request start: {label} domain={domain} timeout={timeout}s attempt={attempt}/{attempts}")
        try:
            data = fetch_json(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if logger:
                logger.error(
                    f"external request failed: {label} domain={domain} elapsed={time.monotonic() - started:.1f}s error={exc}"
                )
            continue
        if logger:
            rows = len(data) if isinstance(data, list) else "unknown"
            logger.info(f"external request end: {label} domain={domain} elapsed={time.monotonic() - started:.1f}s rows={rows}")
        return data
    raise RuntimeError(str(last_error) if last_error else "unknown error")


def add_owned_name(names: set[str], value: str, domain: str) -> None:
    host = value.strip().lower().strip("*.").strip(".")
    if host == domain or host.endswith("." + domain):
        names.add(host)
