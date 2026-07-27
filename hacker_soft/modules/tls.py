from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import tls_certificate_summary


class TlsModule(ScannerModule):
    name = "tls"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        hosts = sorted({context.target.domain, *context.subdomains})[: context.config.max_hosts]
        checked = 0
        for host in hosts:
            try:
                cert = tls_certificate_summary(host, timeout=context.config.timeout_seconds)
            except Exception:
                continue
            checked += 1
            self._expiry_finding(host, cert, result)
            self._protocol_finding(host, cert, result)
        result.artifacts["checked_hosts"] = checked
        return result

    def _expiry_finding(self, host: str, cert: dict, result: ModuleResult) -> None:
        not_after = cert.get("not_after")
        if not not_after:
            return
        try:
            expires_at = parsedate_to_datetime(not_after)
        except Exception:
            return
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        days_left = (expires_at - datetime.now(timezone.utc)).days
        if days_left < 0:
            severity = Severity.HIGH
            title = "TLS-сертификат истек"
        elif days_left <= 14:
            severity = Severity.MEDIUM
            title = "TLS-сертификат скоро истекает"
        else:
            return
        result.findings.append(
            Finding(
                module=self.name,
                title=title,
                severity=severity,
                confidence=Confidence.HIGH,
                target=host,
                evidence={"not_after": not_after, "days_left": days_left},
                recommendation="Обнови сертификат и проверь автоматическое продление для этого хоста.",
                explanation="TLS-сертификат отвечает за HTTPS-доверие и шифрование соединения.",
                impact="Просроченный или скоро истекающий сертификат может сломать доступ пользователей к сайту.",
                fix="Обновить сертификат и проверить автоматическое продление.",
            )
        )

    def _protocol_finding(self, host: str, cert: dict, result: ModuleResult) -> None:
        version = str(cert.get("version", ""))
        if version in {"TLSv1", "TLSv1.1"}:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Поддерживается устаревший TLS-протокол",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    target=host,
                    evidence={"tls_version": version},
                    recommendation="Отключи TLS 1.0/1.1 и оставь TLS 1.2/1.3.",
                    explanation="Сервис принимает старую версию TLS.",
                    impact="Старые TLS-протоколы считаются небезопасными и могут нарушать требования комплаенса.",
                    fix="Отключить TLS 1.0/1.1 в настройках сервера или балансировщика.",
                )
            )
