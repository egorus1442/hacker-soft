from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import (
    LEGACY_TLS_VERSIONS,
    tls_certificate_summary,
    tls_validation_state,
    tls_version_state,
)


VALIDATION_MESSAGES = {
    "hostname_mismatch": (
        "Сертификат выписан не на это имя",
        Severity.MEDIUM,
        "Сертификат хоста не содержит его собственное имя, поэтому браузер считает соединение недоверенным.",
        "Пользователи видят предупреждение безопасности, а часть клиентов и мобильных приложений просто не подключится.",
        "Перевыпустить сертификат с нужным именем в SAN или отдать этот хост тому сертификату, где имя уже есть.",
    ),
    "expired": (
        "Сертификат не проходит проверку из-за срока действия",
        Severity.HIGH,
        "Проверка доверия завершилась ошибкой срока действия сертификата.",
        "HTTPS-доступ к сервису фактически сломан для обычных пользователей.",
        "Обновить сертификат и включить автопродление.",
    ),
    "self_signed": (
        "Используется самоподписанный сертификат",
        Severity.MEDIUM,
        "Сертификат подписан сам собой, а не публичным центром сертификации.",
        "Браузеры считают такое соединение недоверенным, а пользователи привыкают игнорировать предупреждения.",
        "Выпустить сертификат в публичном CA или закрыть сервис от внешнего доступа.",
    ),
    "untrusted_chain": (
        "Цепочка сертификатов неполная или недоверенная",
        Severity.MEDIUM,
        "Сервер не отдает промежуточные сертификаты либо CA не входит в публичные хранилища доверия.",
        "Часть клиентов, особенно мобильные приложения и старые устройства, не сможет установить соединение.",
        "Настроить выдачу полной цепочки сертификатов на сервере или балансировщике.",
    ),
    "verification_failed": (
        "Сертификат не проходит стандартную проверку доверия",
        Severity.MEDIUM,
        "Проверка сертификата стандартным хранилищем доверия завершилась ошибкой.",
        "Соединение может выглядеть небезопасным для пользователей и клиентских приложений.",
        "Разобрать причину по деталям ошибки и перевыпустить или переустановить сертификат.",
    ),
}


class TlsModule(ScannerModule):
    name = "tls"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        hosts = sorted({context.target.domain, *context.subdomains})[: context.config.max_hosts]
        timeout = context.config.timeout_seconds
        checked = 0
        unreachable: list[str] = []
        legacy_by_host: dict[str, list[str]] = {}
        legacy_unknown: dict[str, str] = {}
        negotiated: dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=min(16, max(1, len(hosts)))) as pool:
            future_map = {pool.submit(self._inspect_host, host, timeout): host for host in hosts}
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    report = future.result()
                except Exception:  # noqa: BLE001 - one broken host must not stop the module.
                    continue
                if report["unreachable"]:
                    unreachable.append(host)
                    continue
                checked += 1

                validation = report["validation"]
                if validation["state"] not in {"valid", "handshake_failed"}:
                    self._validation_finding(host, validation, result)
                if report["cert"]:
                    negotiated[host] = str(report["cert"].get("version") or "")
                    self._expiry_finding(host, report["cert"], result)
                if report["legacy"]:
                    legacy_by_host[host] = report["legacy"]
                elif report["legacy_unknown"]:
                    legacy_unknown[host] = report["legacy_unknown"]
        unreachable.sort()

        result.artifacts["checked_hosts"] = checked
        result.artifacts["tls_unreachable_hosts"] = unreachable
        result.artifacts["negotiated_versions"] = negotiated
        if legacy_unknown:
            result.artifacts["legacy_tls_not_verified"] = legacy_unknown
            result.errors.append(
                "проверка TLS 1.0/1.1 не выполнена: локальный OpenSSL отказывается открывать устаревшие "
                f"протоколы ({len(legacy_unknown)} хостов); результат по ним неизвестен, а не «чисто»"
            )
        if legacy_by_host:
            self._legacy_finding(legacy_by_host, result)
        return result

    def _inspect_host(self, host: str, timeout: int) -> dict[str, object]:
        validation = tls_validation_state(host, timeout=timeout)
        if validation["state"] == "unreachable":
            return {"unreachable": True, "validation": validation, "cert": {}, "legacy": [], "legacy_unknown": ""}
        try:
            cert = tls_certificate_summary(host, timeout=timeout)
        except Exception:  # noqa: BLE001 - an untrusted certificate still gets a finding above.
            cert = {}
        legacy, legacy_unknown = self._probe_legacy_versions(host, timeout)
        return {
            "unreachable": False,
            "validation": validation,
            "cert": cert,
            "legacy": legacy,
            "legacy_unknown": legacy_unknown,
        }

    def _probe_legacy_versions(self, host: str, timeout: int) -> tuple[list[str], str]:
        supported: list[str] = []
        unknown_reason = ""
        for version in LEGACY_TLS_VERSIONS:
            state = tls_version_state(host, version, timeout=timeout)
            if state["state"] == "supported":
                supported.append(version)
            elif state["state"] == "unknown" and not unknown_reason:
                unknown_reason = state["detail"]
        return supported, unknown_reason

    def _validation_finding(self, host: str, validation: dict[str, str], result: ModuleResult) -> None:
        title, severity, explanation, impact, fix = VALIDATION_MESSAGES.get(
            validation["state"], VALIDATION_MESSAGES["verification_failed"]
        )
        result.findings.append(
            Finding(
                module=self.name,
                title=title,
                severity=severity,
                confidence=Confidence.HIGH,
                target=host,
                evidence={"validation_state": validation["state"], "detail": validation["detail"]},
                recommendation=fix,
                explanation=explanation,
                impact=impact,
                fix=fix,
            )
        )

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
        elif days_left <= 30:
            severity = Severity.LOW
            title = "TLS-сертификат истекает в течение месяца"
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

    def _legacy_finding(self, legacy_by_host: dict[str, list[str]], result: ModuleResult) -> None:
        versions = sorted({version for versions in legacy_by_host.values() for version in versions})
        result.findings.append(
            Finding(
                module=self.name,
                title="Сервисы принимают устаревшие версии TLS",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                target=", ".join(sorted(legacy_by_host)[:5]),
                evidence={"hosts": legacy_by_host, "versions": versions},
                recommendation="Отключи TLS 1.0/1.1 и оставь только TLS 1.2 и 1.3.",
                explanation=(
                    "Сканер отдельно установил соединение по каждой старой версии протокола, и эти хосты "
                    "согласились работать по устаревшему TLS."
                ),
                impact="TLS 1.0/1.1 считаются небезопасными и нарушают требования PCI DSS и большинства политик комплаенса.",
                fix="Поднять минимальную версию TLS до 1.2 в настройках сервера, балансировщика или CDN.",
            )
        )
