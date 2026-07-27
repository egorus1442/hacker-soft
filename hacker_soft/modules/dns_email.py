from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import USER_AGENT, resolve_host, run_tool


DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]


class DnsEmailModule(ScannerModule):
    name = "dns_email"
    passive = True

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        domain = context.target.domain
        records: dict[str, list[str]] = {}
        successful_types: set[str] = set()

        for record_type in DNS_TYPES:
            values, error = lookup_dns(domain, record_type, context.config.timeout_seconds, context.logger)
            if error:
                result.errors.append(error)
                if record_type == "A":
                    values = resolve_host(domain)
            if error and not values:
                continue
            successful_types.add(record_type)
            records[record_type] = sorted({line.strip() for line in values if line.strip()})

        context.dns_records[domain] = records
        self._email_findings(domain, records, successful_types, result, context.config.timeout_seconds, context.logger)
        self._caa_findings(domain, records, successful_types, result)
        return result

    def _email_findings(
        self,
        domain: str,
        records: dict[str, list[str]],
        successful_types: set[str],
        result: ModuleResult,
        timeout: int,
        logger=None,
    ) -> None:
        if "TXT" not in successful_types:
            result.errors.append("TXT-запрос не завершился; SPF/DMARC-находки пропущены, чтобы не плодить ложные срабатывания")
            return

        txt = " ".join(records.get("TXT", []))
        has_spf = "v=spf1" in txt.lower()
        has_dmarc = False
        dmarc_records: list[str] = []

        dmarc_records, dmarc_error = lookup_dns(f"_dmarc.{domain}", "TXT", timeout, logger)
        if not dmarc_error:
            dmarc_records = [line.strip().strip('"') for line in dmarc_records if line.strip()]
            has_dmarc = any("V=DMARC1" in line.upper() for line in dmarc_records)
        else:
            result.errors.append("DMARC-запрос не завершился; DMARC-находки пропущены, чтобы не плодить ложные срабатывания")

        if not has_spf:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Отсутствует SPF-запись",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    target=domain,
                    evidence={"txt_records": records.get("TXT", [])[:10]},
                    recommendation="Опубликуй SPF-запись и оставь в ней только разрешенные источники корпоративной почты.",
                    explanation="SPF - это DNS-настройка, которая говорит почтовым сервисам, кто имеет право отправлять письма от имени домена.",
                    impact="Без SPF мошенникам проще подделывать письма от имени компании, а нормальная почта может хуже доставляться.",
                    fix="Добавить SPF-запись в DNS и перечислить только реальные почтовые сервисы компании.",
                )
            )

        if not dmarc_error and not has_dmarc:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Отсутствует DMARC-запись",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    target=domain,
                    evidence={"dmarc_records": dmarc_records},
                    recommendation="Опубликуй DMARC-запись и после мониторинга переведи политику к quarantine или reject.",
                    explanation="DMARC - это политика защиты доменной почты от подделки.",
                    impact="Без DMARC сложнее бороться с фишинговыми письмами, которые выглядят как письма от вашей компании.",
                    fix="Добавить DMARC-запись, сначала собрать отчеты, затем перевести политику к quarantine или reject.",
                )
            )
            return

        joined = " ".join(dmarc_records).lower()
        policy = re.search(r"\bp=([a-z]+)", joined)
        if policy and policy.group(1) == "none":
            result.findings.append(
                Finding(
                    module=self.name,
                    title="DMARC работает только в режиме мониторинга",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    target=domain,
                    evidence={"dmarc_records": dmarc_records},
                    recommendation="После проверки легитимных отправителей переведи DMARC-политику в quarantine или reject.",
                    explanation="DMARC уже есть, но сейчас он только наблюдает и не просит почтовые сервисы блокировать подозрительные письма.",
                    impact="Фишинговые письма от имени домена могут продолжать доходить до получателей.",
                    fix="Проверить легитимные источники почты и усилить политику DMARC до quarantine или reject.",
                )
            )

    def _caa_findings(
        self,
        domain: str,
        records: dict[str, list[str]],
        successful_types: set[str],
        result: ModuleResult,
    ) -> None:
        if "CAA" not in successful_types:
            result.errors.append("CAA-запрос не завершился; CAA-находки пропущены, чтобы не плодить ложные срабатывания")
            return
        if not records.get("CAA"):
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Отсутствует CAA-запись",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    target=domain,
                    evidence={},
                    recommendation="Опубликуй CAA-записи, чтобы ограничить центры сертификации, которым разрешена выдача сертификатов.",
                    explanation="CAA - это DNS-настройка, которая ограничивает, какие центры сертификации могут выпускать HTTPS-сертификаты для домена.",
                    impact="Без CAA контроль над выпуском сертификатов слабее, особенно если в инфраструктуре много доменов и подрядчиков.",
                    fix="Добавить CAA-записи для используемых центров сертификации, например Let's Encrypt или другого вашего CA.",
                )
            )


def lookup_dns(name: str, record_type: str, timeout: int, logger=None) -> tuple[list[str], str | None]:
    dig_values, dig_error = lookup_with_dig(name, record_type, timeout, logger)
    if dig_values:
        return dig_values, None

    doh_values, doh_error = lookup_with_dns_google(name, record_type, min(timeout, 8))
    if doh_error is None:
        return doh_values, None

    if dig_error and doh_error:
        return [], f"{dig_error}; DNS-over-HTTPS тоже не сработал: {doh_error}"
    return [], dig_error or doh_error


def lookup_with_dig(name: str, record_type: str, timeout: int, logger=None) -> tuple[list[str], str | None]:
    dig_timeout = max(1, min(timeout, 4))
    args = ["dig", f"+time={dig_timeout}", "+tries=1", "+short", name, record_type]
    code, stdout, stderr = run_tool(args, timeout=dig_timeout + 2, logger=logger)
    if code == 127:
        return [], "dig не найден"
    if code != 0:
        return [], f"dig {record_type} завершился ошибкой: {stderr.strip() or 'timeout'}"
    return [line.strip().strip('"') for line in stdout.splitlines() if line.strip()], None


def lookup_with_dns_google(name: str, record_type: str, timeout: int) -> tuple[list[str], str | None]:
    query = urllib.parse.urlencode({"name": name, "type": record_type})
    request = urllib.request.Request(
        f"https://dns.google/resolve?{query}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return lookup_with_cloudflare_dns(name, record_type, timeout, str(exc))

    status = payload.get("Status")
    if status not in {0, 3, None}:
        return [], f"dns.google status={status}"

    answers = payload.get("Answer") or []
    values = []
    for answer in answers:
        data = str(answer.get("data", "")).strip()
        if not data:
            continue
        values.append(data.strip('"').strip())
    return values, None




def lookup_with_cloudflare_dns(
    name: str,
    record_type: str,
    timeout: int,
    previous_error: str,
) -> tuple[list[str], str | None]:
    query = urllib.parse.urlencode({"name": name, "type": record_type})
    request = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?{query}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [], f"dns.google: {previous_error}; cloudflare-dns: {exc}"

    status = payload.get("Status")
    if status not in {0, 3, None}:
        return [], f"cloudflare-dns status={status}"

    answers = payload.get("Answer") or []
    values = []
    for answer in answers:
        data = str(answer.get("data", "")).strip()
        if data:
            values.append(data.strip('"').strip())
    return values, None
