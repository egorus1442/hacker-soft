from __future__ import annotations

import html
import json
import os
import re
import socket
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse, urlunparse, urldefrag

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import USER_AGENT, run_tool


RISKY_PORTS = {
    21: ("FTP", Severity.HIGH, "FTP часто передает данные без нормального шифрования и не должен быть открыт всем."),
    1433: ("MSSQL", Severity.CRITICAL, "Публичный порт базы данных резко повышает риск перебора, эксплуатации CVE и утечки данных."),
    1521: ("Oracle Database", Severity.CRITICAL, "Публичный порт базы данных резко повышает риск перебора, эксплуатации CVE и утечки данных."),
    2049: ("NFS", Severity.CRITICAL, "Публичный NFS может раскрыть файловые шары или внутренние данные."),
    2375: ("Docker API", Severity.CRITICAL, "Открытый Docker API без строгой защиты может дать контроль над хостом."),
    2376: ("Docker API TLS", Severity.HIGH, "Docker API должен быть доступен только из приватной сети или по allowlist."),
    3306: ("MySQL", Severity.CRITICAL, "Публичный порт базы данных резко повышает риск перебора, эксплуатации CVE и утечки данных."),
    3389: ("RDP", Severity.HIGH, "RDP в интернет часто становится целью перебора и эксплуатации."),
    5432: ("PostgreSQL", Severity.CRITICAL, "Публичный порт базы данных резко повышает риск перебора, эксплуатации CVE и утечки данных."),
    5601: ("Kibana", Severity.HIGH, "Публичная Kibana может раскрывать внутренние логи и административные функции."),
    5900: ("VNC", Severity.HIGH, "VNC в интернет часто приводит к риску удаленного доступа."),
    6379: ("Redis", Severity.CRITICAL, "Redis обычно не должен быть публичным; ошибки конфигурации могут привести к компрометации."),
    9200: ("Elasticsearch", Severity.CRITICAL, "Публичный Elasticsearch может раскрыть данные и индексы."),
    9300: ("Elasticsearch transport", Severity.CRITICAL, "Transport-порт Elasticsearch не должен быть доступен из интернета."),
    11211: ("Memcached", Severity.HIGH, "Публичный Memcached может раскрывать данные и участвовать в amplification-атаках."),
    27017: ("MongoDB", Severity.CRITICAL, "Публичный MongoDB может привести к утечке данных при слабой конфигурации."),
}

CONTROL_PORTS = [1, 2, 3, 7, 9, 13, 37, 79, 81, 82, 999, 1234, 4444, 10001, 23456, 34567, 45678, 65000]
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp", "zip", "rar", "7z"}
DOCUMENT_CONTENT_TYPES = (
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.oasis.opendocument",
    "application/rtf",
    "application/zip",
    "application/x-rar",
    "application/x-7z-compressed",
)
DOCUMENT_MAGIC_PREFIXES = (
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"{\\rtf",
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
    b"7z\xbc\xaf\x27\x1c",
)
DOCUMENT_KEYWORDS = {
    "confidential",
    "internal",
    "private",
    "restricted",
    "contract",
    "invoice",
    "budget",
    "salary",
    "personal",
    "passport",
    "договор",
    "контракт",
    "конфиденц",
    "зарплат",
    "паспорт",
    "персональн",
    "заявк",
}
ABSOLUTE_URL_RE = re.compile(r"""https?://[^\\\"' <>\s)]+""", re.IGNORECASE)
ATTR_URL_RE = re.compile(r"""(?:href|src|data|action)=["']([^"']+)["']""", re.IGNORECASE)


class KatanaLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if key and key.lower() in {"href", "src", "data", "action"} and value:
                self.links.append(value)


class ProjectDiscoveryModule(ScannerModule):
    name = "projectdiscovery"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.with_tools:
            result.artifacts["skipped"] = "требуется --with-tools"
            return result

        context.config.out_dir.mkdir(parents=True, exist_ok=True)
        self._subfinder(context, result)
        self._dnsx(context, result)
        self._httpx(context, result)
        if context.config.active:
            self._naabu(context, result)
            self._katana(context, result)
            self._nuclei(context, result)
        return result

    def _subfinder(self, context: ScanContext, result: ModuleResult) -> None:
        args = ["subfinder", "-silent", "-json", "-all", "-d", context.target.domain]
        code, stdout, stderr = run_tool(args, timeout=240, logger=context.logger)
        if code == 127:
            result.errors.append("subfinder не найден")
            return
        if code != 0 and not stdout:
            result.errors.append(f"subfinder завершился ошибкой: {stderr.strip()[:500]}")
            return

        hosts = set()
        for line in stdout.splitlines():
            item = parse_json_line(line)
            host = item.get("host") if item else line.strip()
            if is_owned_host(host, context.target.domain):
                hosts.add(host.lower().strip("."))
        context.subdomains.update(hosts)
        result.artifacts["subfinder_count"] = len(hosts)

    def _dnsx(self, context: ScanContext, result: ModuleResult) -> None:
        hosts = sorted({context.target.domain, *context.subdomains})[: context.config.max_hosts]
        if not hosts:
            return
        code, stdout, stderr = run_tool(
            ["dnsx", "-silent", "-json", "-a", "-aaaa", "-cname", "-resp"],
            timeout=180,
            input_text="\n".join(hosts) + "\n",
            logger=context.logger,
        )
        if code == 127:
            result.errors.append("dnsx не найден")
            return
        if code != 0 and not stdout:
            result.errors.append(f"dnsx завершился ошибкой: {stderr.strip()[:500]}")
            return

        resolved = 0
        for line in stdout.splitlines():
            item = parse_json_line(line)
            if not item:
                continue
            host = item.get("host") or item.get("input")
            if is_owned_host(host, context.target.domain):
                context.subdomains.add(host.lower().strip("."))
            for key in ("a", "aaaa"):
                values = item.get(key) or []
                if isinstance(values, str):
                    values = [values]
                context.ips.update(str(value) for value in values if value)
            resolved += 1
        result.artifacts["dnsx_resolved"] = resolved

    def _httpx(self, context: ScanContext, result: ModuleResult) -> None:
        hosts = sorted({context.target.domain, *context.subdomains})[: context.config.max_hosts]
        if not hosts:
            return
        args = [
            "httpx",
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-location",
            "-server",
            "-follow-host-redirects",
            "-rate-limit",
            "50",
        ]
        code, stdout, stderr = run_tool(args, timeout=300, input_text="\n".join(hosts) + "\n", logger=context.logger)
        if code == 127:
            result.errors.append("httpx не найден")
            return
        if code != 0 and not stdout:
            result.errors.append(f"httpx завершился ошибкой: {stderr.strip()[:500]}")
            return

        live = 0
        live_hosts = set()
        for line in stdout.splitlines():
            item = parse_json_line(line)
            if not item:
                continue
            url = item.get("url")
            if not url:
                continue
            context.live_hosts.add(url)
            parsed_host = urlparse(url).hostname
            if is_owned_host(parsed_host, context.target.domain):
                live_hosts.add(parsed_host.lower().strip("."))
            context.http_services[url] = {
                "status": item.get("status_code"),
                "title": item.get("title"),
                "webserver": item.get("webserver"),
                "tech": item.get("tech"),
                "content_length": item.get("content_length"),
                "location": item.get("location"),
                "source": "projectdiscovery/httpx",
            }
            live += 1
            tech = item.get("tech") or []
            if tech:
                result.findings.append(
                    Finding(
                        module=self.name,
                        title="Технологии веб-сервиса определены через httpx",
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        target=url,
                        evidence={"tech": tech, "title": item.get("title"), "status": item.get("status_code")},
                        recommendation="Проверь версии и владельцев технологий, особенно для публичных админок и старых стеков.",
                        explanation="httpx определил технологии, которые использует публичный веб-сервис.",
                        impact="Само по себе это информационная находка, но она помогает понять, какие сервисы нужно обновлять и мониторить.",
                        fix="Проверить владельца сервиса, актуальность технологий и отсутствие старых публичных админок.",
                    )
                )
        result.artifacts["httpx_live"] = live
        result.artifacts["httpx_live_hosts"] = len(live_hosts)
        result.artifacts["httpx_checked_hosts"] = len(hosts)
        if context.subdomains and not live_hosts:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Поддомены найдены, но живые HTTP(S)-сервисы не подтвердились",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    target=context.target.domain,
                    evidence={"subdomains": len(context.subdomains), "checked_hosts": len(hosts)},
                    recommendation="Проверь поддомены вручную и убедись, что они не доступны только по нестандартным портам или из внутренней сети.",
                    explanation="Сканер нашел DNS-имена, но httpx не увидел на них живых веб-сервисов по HTTP/HTTPS.",
                    impact="Часть поверхности может быть не веб-сайтами, а API, админками или сервисами на нестандартных портах.",
                    fix="Проверить владельцев поддоменов, ожидаемые сервисы и закрыть лишние записи DNS.",
                )
            )

    def _naabu(self, context: ScanContext, result: ModuleResult) -> None:
        hosts = sorted({context.target.domain, *context.subdomains})[: min(context.config.max_hosts, 200)]
        if not hosts:
            return
        args = [
            "naabu",
            "-silent",
            "-json",
            "-scan-type",
            "c",
            "-top-ports",
            "100",
            "-rate",
            "200",
        ]
        code, stdout, stderr = run_tool(
            args,
            timeout=tool_timeout(context, default=900, minimum=240, multiplier=60),
            input_text="\n".join(hosts) + "\n",
            logger=context.logger,
        )
        if code == 127:
            result.errors.append("naabu не найден")
            return
        if code != 0 and not stdout:
            result.errors.append(f"naabu завершился ошибкой: {stderr.strip()[:500]}")
            return

        count = 0
        port_details: dict[str, list[int]] = {}
        for line in stdout.splitlines():
            item = parse_json_line(line)
            if not item:
                continue
            host = str(item.get("host") or item.get("ip") or "").strip()
            port = item.get("port")
            if not host or not port:
                continue
            try:
                port_number = int(port)
            except (TypeError, ValueError):
                continue
            context.open_ports.setdefault(host, set()).add(port_number)
            port_details.setdefault(host, []).append(port_number)
            count += 1
        if count:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="naabu нашел открытые порты",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    target=context.target.domain,
                    evidence={"count": count},
                    recommendation="Сверь порты с картой периметра и смотри отдельный блок banner checks: риск выставляется только там, где сервис ответил баннером.",
                    explanation="naabu увидел порты, на которых TCP-connect выглядит успешным.",
                    impact="Без баннера это еще не подтверждает конкретный сервис: так может вести себя firewall, proxy, tarpit или сервис, который молчит до корректного handshake.",
                    fix="Закрывать как уязвимость только подтвержденные сервисы; неподтвержденные порты перепроверить nmap -sV или ручным клиентом.",
                )
            )
        result.artifacts["naabu_open_ports"] = count
        result.artifacts["naabu_open_ports_by_host"] = {host: sorted(set(ports)) for host, ports in port_details.items()}
        banner_checks = collect_port_banners(port_details)
        result.artifacts["port_banner_checks"] = banner_checks
        no_banner_ports = {
            host: sorted(int(port) for port, banner in ports.items() if not banner.get("banner_found"))
            for host, ports in banner_checks.items()
        }
        no_banner_ports = {host: ports for host, ports in no_banner_ports.items() if ports}
        if no_banner_ports:
            result.artifacts["open_ports_without_banners"] = no_banner_ports
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Открытые TCP-порты без подтвержденного баннера",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    target=context.target.domain,
                    evidence={"hosts": no_banner_ports},
                    recommendation="Не считать эти порты уязвимостью без дополнительного подтверждения сервиса. При необходимости перепроверить nmap -sV или ручным клиентом.",
                    explanation="TCP-соединение установилось, но сервис не прислал баннер или распознаваемый ответ.",
                    impact="Такой порт может быть реальным сервисом, firewall/tarpit/proxy-ответом или сервисом, который молчит до корректного клиентского handshake.",
                    fix="Оставить как информационную находку до подтверждения конкретного сервиса и владельца.",
                )
            )
        risky_by_host: dict[str, dict[str, dict[str, str]]] = {}
        max_severity = Severity.INFO
        for host, ports in sorted(port_details.items()):
            risky_ports = {}
            for port in sorted(set(ports)):
                if port not in RISKY_PORTS:
                    continue
                banner = banner_checks.get(host, {}).get(str(port), {})
                if not banner.get("banner_found"):
                    continue
                service, severity, reason = RISKY_PORTS[port]
                risky_ports[str(port)] = {
                    "service": service,
                    "reason": reason,
                    "banner": str(banner.get("banner") or ""),
                }
                max_severity = highest_severity(max_severity, severity)
            if risky_ports:
                risky_by_host[host] = risky_ports

        noisy_hosts = {
            host: {
                "reason": "too_many_open_ports",
                "open_port_count": len(set(ports)),
                "sample": sorted(set(ports))[:30],
            }
            for host, ports in port_details.items()
            if len(set(ports)) >= 30
        }
        for host, ports in sorted(port_details.items()):
            if host in noisy_hosts or len(set(ports)) < 5:
                continue
            control_evidence = probe_accept_all_host(host, set(ports))
            if control_evidence:
                noisy_hosts[host] = {
                    "reason": "control_ports_also_open",
                    "open_ports": sorted(set(ports)),
                    **control_evidence,
                }
        if noisy_hosts:
            result.artifacts["naabu_noisy_hosts"] = noisy_hosts
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Результат port scan выглядит шумным и требует перепроверки",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    target=context.target.domain,
                    evidence=result.artifacts["naabu_noisy_hosts"],
                    recommendation="Перепроверь порты баннер-грабом или nmap -sV с небольшой скоростью перед тем, как считать их реальной поверхностью атаки.",
                    explanation="Сканер увидел слишком много открытых top-портов на одном host, что часто бывает из-за tarpitting, firewall/proxy-ответов или сетевых особенностей.",
                    impact="Отчет может завысить риск и показать как открытые порты, которые на самом деле не ведут к рабочим сервисам.",
                    fix="Запустить ручную проверку ключевых портов и оставить в плане исправлений только подтвержденные сервисы.",
                )
            )
            if not risky_by_host:
                return
        if risky_by_host:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Потенциально опасные сетевые сервисы доступны из интернета",
                    severity=max_severity,
                    confidence=Confidence.HIGH,
                    target=context.target.domain,
                    evidence={"hosts": risky_by_host, "note": "Риск выставлен только для портов, где удалось получить баннер/ответ сервиса."},
                    recommendation="Подтверди владельца сервиса и закрой базы данных, админские и remote-access порты через VPN или allowlist.",
                    explanation="Сканер увидел открытые порты и получил баннер/ответ от сервиса на рискованном порту.",
                    impact="Подтвержденный публичный сервис базы данных, удаленного доступа или админского API может быть критичным риском.",
                    fix="Проверить владельца каждого порта, подтвердить сервис и ограничить доступ firewall/VPN/private network.",
                )
            )
    def _katana(self, context: ScanContext, result: ModuleResult) -> None:
        urls = sorted(context.live_hosts)[:80]
        if not urls:
            return
        output_file = context.config.out_dir / "katana-output.jsonl"
        error_log = context.config.out_dir / "katana-errors.log"
        args = [
            "katana",
            "-silent",
            "-jsonl",
            "-depth",
            "2",
            "-concurrency",
            "10",
            "-rate-limit",
            "50",
            "-output",
            str(output_file),
            "-elog",
            str(error_log),
        ]
        if context.logger:
            context.logger.info(f"katana output file: {output_file}")
        code, stdout, stderr = run_tool(
            args,
            timeout=tool_timeout(context, default=180, minimum=90, multiplier=18),
            input_text="\n".join(urls) + "\n",
            logger=context.logger,
            stdout_path=Path(os.devnull),
        )
        if code == 127:
            result.errors.append("katana не найден")
            return
        lines = collect_jsonl_lines(stdout, output_file)
        result.artifacts["katana_output"] = artifact_info(output_file)
        result.artifacts["katana_error_log"] = artifact_info(error_log)
        if code != 0 and not lines:
            result.errors.append(
                f"katana завершился ошибкой: {stderr.strip()[:500]}; error_log={error_log}"
            )
            return
        if code != 0:
            result.errors.append(
                f"katana завершился ошибкой: {stderr.strip()[:500]}, но частичные endpoints сохранены; "
                f"output={output_file}; error_log={error_log}"
            )

        endpoints = set()
        for line in lines:
            item = parse_json_line(line)
            url = (item or {}).get("request", {}).get("endpoint") or (item or {}).get("url") or line.strip()
            if is_owned_url(url, context.target.domain):
                endpoints.add(url)
        context.endpoints.update(sorted(endpoints)[:1000])
        result.artifacts["katana_endpoints"] = len(endpoints)
        document_summary = verify_document_summary(
            extract_documents_from_katana(output_file, context.target.domain),
            context,
        )
        if document_summary["total"]:
            document_artifact = write_document_artifact(context, document_summary["documents"])
            result.artifacts["public_documents"] = {
                "total": document_summary["total"],
                "by_type": document_summary["by_type"],
                "by_host": document_summary["by_host"],
                "keyword_matches": document_summary["keyword_matches"],
                "sample": document_summary["sample"],
                "documents": document_summary["documents"],
                "full_list": document_artifact,
                "checked_total": document_summary.get("checked_total", document_summary["total"]),
                "rejected_total": document_summary.get("rejected_total", 0),
            }
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Публичные документы найдены на сайте",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    target=context.target.domain,
                    evidence={
                        "total": document_summary["total"],
                        "by_type": document_summary["by_type"],
                        "keyword_matches": document_summary["keyword_matches"],
                        "sample": document_summary["sample"][:10],
                    },
                    recommendation="Проверить список документов и отдельно разобрать файлы с чувствительными словами в названии.",
                    explanation="Краулер нашел и проверил публичные PDF/Office-документы по ссылкам внутри страниц сайта.",
                    impact="Публичные документы сами по себе не всегда проблема, но в них могут быть метаданные, договоры, заявки, внутренние названия и контакты.",
                    fix="Сверить документы с политикой публикации, убрать лишнее из публичного доступа и очищать метаданные перед публикацией.",
                )
            )
        if len(endpoints) > 300:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Большая публичная карта endpoints",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    target=context.target.domain,
                    evidence={"endpoint_count": len(endpoints)},
                    recommendation="Проверь endpoints на старые API, debug-ручки, тестовые страницы и лишнюю индексацию.",
                    explanation="Краулер нашел много публичных URL и API-ручек.",
                    impact="Среди них могут быть старые API, тестовые страницы или служебные endpoints без нормального контроля доступа.",
                    fix="Проверить список endpoints, закрыть служебные ручки и удалить устаревшие маршруты.",
                )
            )

    def _nuclei(self, context: ScanContext, result: ModuleResult) -> None:
        urls = sorted(context.live_hosts)[:100]
        if not urls:
            return
        target_file = context.config.out_dir / "nuclei-targets.txt"
        output_file = context.config.out_dir / "nuclei-output.jsonl"
        error_log = context.config.out_dir / "nuclei-errors.log"
        trace_log = context.config.out_dir / "nuclei-trace.log"
        stdout_log = context.config.out_dir / "nuclei-stdout.log"
        stderr_log = context.config.out_dir / "nuclei-stderr.log"
        target_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        args = [
            "nuclei",
            "-list",
            str(target_file),
            "-severity",
            "low,medium,high,critical",
            "-jsonl",
            "-jsonl-export",
            str(output_file),
            "-silent",
            "-rate-limit",
            "25",
            "-elog",
            str(error_log),
            "-tlog",
            str(trace_log),
            "-hm",
            "-stats",
            "-stats-interval",
            "30",
        ]
        if context.logger:
            context.logger.info(
                f"nuclei targets file: {target_file} targets={len(urls)} "
                f"output={output_file} error_log={error_log} trace_log={trace_log} "
                f"stdout_log={stdout_log} stderr_log={stderr_log}"
            )
        code, stdout, stderr = run_tool(
            args,
            timeout=tool_timeout(context, default=900, minimum=300, multiplier=75),
            logger=context.logger,
            stdout_path=stdout_log,
            stderr_path=stderr_log,
        )
        if code == 127:
            result.errors.append("nuclei не найден")
            return
        lines = collect_jsonl_lines(stdout, output_file)
        result.artifacts["nuclei_output"] = artifact_info(output_file)
        result.artifacts["nuclei_error_log"] = artifact_info(error_log)
        result.artifacts["nuclei_trace_log"] = artifact_info(trace_log)
        result.artifacts["nuclei_stdout_log"] = artifact_info(stdout_log)
        result.artifacts["nuclei_stderr_log"] = artifact_info(stderr_log)
        result.artifacts["nuclei_stderr_tail"] = tail_lines(stderr_log)
        result.artifacts["nuclei_error_tail"] = tail_lines(error_log)
        result.artifacts["nuclei_trace_tail"] = tail_lines(trace_log)
        if context.logger:
            context.logger.info(
                "nuclei artifacts: "
                f"output_size={file_size(output_file)} error_log_size={file_size(error_log)} "
                f"trace_log_size={file_size(trace_log)} stdout_size={file_size(stdout_log)} "
                f"stderr_size={file_size(stderr_log)} jsonl_lines={len(lines)}"
            )
        if code != 0 and not lines:
            result.errors.append(
                f"nuclei завершился ошибкой: {stderr.strip()[:500]}; частичных JSONL-находок нет; "
                f"stderr_log={stderr_log}; error_log={error_log}; trace_log={trace_log}"
            )
            return
        if code != 0:
            result.errors.append(
                f"nuclei завершился ошибкой: {stderr.strip()[:500]}, но частичные находки сохранены; "
                f"output={output_file}; stderr_log={stderr_log}; error_log={error_log}; trace_log={trace_log}"
            )

        count = 0
        seen = set()
        for line in lines:
            item = parse_json_line(line)
            if not item:
                continue
            fingerprint = (
                item.get("template-id"),
                item.get("matched-at") or item.get("host"),
                item.get("matcher-name"),
                (item.get("info") or {}).get("name"),
            )
            normalized_fingerprint = normalize_nuclei_fingerprint(item)
            fingerprint = normalized_fingerprint or fingerprint
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
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
                    explanation="Nuclei сработал по шаблону известной уязвимости или неправильной настройки.",
                    impact="Такая находка может указывать на реальную CVE/misconfig, но требует ручного подтверждения.",
                    fix="Открыть цель из доказательств, подтвердить проблему и обновить/перенастроить уязвимый компонент.",
                    references=item.get("template-url") and [item["template-url"]] or [],
                )
            )
            count += 1
        result.artifacts["nuclei_findings"] = count


def extract_documents_from_katana(output_file: Path, domain: str) -> dict[str, object]:
    documents: dict[str, dict[str, str]] = {}
    if not output_file.exists():
        return empty_document_summary()

    with output_file.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            item = parse_json_line(line)
            if not item:
                continue
            endpoint = normalize_candidate_url((item.get("request") or {}).get("endpoint") or item.get("url"))
            base_url = endpoint if endpoint and is_owned_url(endpoint, domain) else f"https://{domain}/"
            add_document_candidate(documents, endpoint, domain)

            response = item.get("response") if isinstance(item.get("response"), dict) else {}
            text = html.unescape(f"{response.get('body') or ''}\n{response.get('raw') or ''}")
            for candidate in iter_link_candidates(text):
                candidate = normalize_candidate_url(candidate)
                if not candidate or candidate.startswith(("mailto:", "javascript:", "tel:")):
                    continue
                add_document_candidate(documents, urljoin(base_url, candidate), domain)

    return summarize_documents(documents)


def empty_document_summary() -> dict[str, object]:
    return {
        "total": 0,
        "by_type": {},
        "by_host": {},
        "keyword_matches": 0,
        "sample": [],
        "documents": [],
    }


def iter_link_candidates(text: str) -> list[str]:
    candidates = []
    candidates.extend(ABSOLUTE_URL_RE.findall(text))
    candidates.extend(ATTR_URL_RE.findall(text))
    try:
        parser = KatanaLinkParser()
        parser.feed(text)
        candidates.extend(parser.links)
    except Exception:  # noqa: BLE001 - malformed HTML should not break report generation.
        pass
    return candidates


def normalize_candidate_url(value: object) -> str | None:
    if not value:
        return None
    url = html.unescape(str(value)).strip().strip("'\"()[]{}<>")
    url = url.replace("\\/", "/")
    return urldefrag(url)[0]


def add_document_candidate(documents: dict[str, dict[str, str]], url: str | None, domain: str) -> None:
    if not url:
        return
    try:
        parsed = urlparse(url)
    except ValueError:
        return
    if parsed.scheme not in {"http", "https"} or not is_owned_host(parsed.hostname, domain):
        return
    extension = document_extension(url)
    if not extension:
        return
    canonical = canonical_document_url(url)
    documents.setdefault(
        canonical,
        {
            "url": canonical,
            "extension": extension,
            "host": urlparse(canonical).netloc,
            "keyword_match": "yes" if has_document_keyword(canonical) else "no",
        },
    )


def document_extension(url: str) -> str | None:
    try:
        path = urlparse(url).path.lower()
    except ValueError:
        return None
    for extension in DOCUMENT_EXTENSIONS:
        if path.endswith("." + extension):
            return extension
    return None


def canonical_document_url(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    port = parsed.port
    netloc = host if port in {None, 80, 443} else f"{host}:{port}"
    path = unquote(parsed.path)
    return urlunparse(("https", netloc, path, "", "", ""))


def has_document_keyword(url: str) -> bool:
    lower_url = url.lower()
    return any(keyword in lower_url for keyword in DOCUMENT_KEYWORDS)


def summarize_documents(documents: dict[str, dict[str, str]]) -> dict[str, object]:
    ordered = [documents[url] for url in sorted(documents)]
    by_type = {}
    by_host = {}
    for item in ordered:
        by_type[item["extension"]] = by_type.get(item["extension"], 0) + 1
        by_host[item["host"]] = by_host.get(item["host"], 0) + 1
    by_type = dict(sorted(by_type.items(), key=lambda item: (-item[1], item[0])))
    by_host = dict(sorted(by_host.items(), key=lambda item: (-item[1], item[0]))[:20])
    keyword_matches = [item for item in ordered if item["keyword_match"] == "yes"]
    sample = keyword_matches[:12] or ordered[:12]
    return {
        "total": len(ordered),
        "by_type": by_type,
        "by_host": by_host,
        "keyword_matches": len(keyword_matches),
        "sample": sample,
        "documents": ordered,
    }


def verify_document_summary(summary: dict[str, object], context: ScanContext) -> dict[str, object]:
    documents = summary.get("documents") if isinstance(summary.get("documents"), list) else []
    if not documents:
        return summary

    timeout = max(6, min(20, context.config.timeout_seconds))
    max_workers = max(1, min(8, len(documents)))
    verified: dict[str, dict[str, str]] = {}
    checked_total = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(verify_document_item, item, timeout) for item in documents if isinstance(item, dict)]
        for future in as_completed(futures):
            checked_total += 1
            item = future.result()
            if item:
                verified[item["url"]] = item

    verified_summary = summarize_documents(verified)
    verified_summary["checked_total"] = checked_total
    verified_summary["rejected_total"] = checked_total - verified_summary["total"]
    return verified_summary


def verify_document_item(item: dict[str, str], timeout: int) -> dict[str, str] | None:
    url = item.get("url", "")
    response = fetch_document_probe(url, timeout=timeout, method="HEAD")
    if response["status"] in {405, 403} or (response["status"] or 0) >= 500:
        response = fetch_document_probe(url, timeout=timeout, method="GET")
    status = response["status"]
    final_url = response["url"] or url
    content_type = response["content_type"]
    if status is None or status >= 400:
        return None
    if not (is_document_content_type(content_type) or document_extension(final_url)):
        return None

    sample = fetch_document_probe(final_url, timeout=timeout, method="GET", byte_range="bytes=0-4095")
    sample_status = sample["status"]
    if sample_status is None or sample_status >= 400 or not looks_like_document_bytes(sample["body"]):
        return None

    canonical = canonical_document_url(sample["url"] or final_url)
    extension = document_extension(canonical)
    if not extension:
        return None
    parsed = urlparse(canonical)
    verified = {
        **item,
        "url": canonical,
        "extension": extension,
        "host": parsed.netloc,
        "status_code": str(sample_status),
        "content_type": sample["content_type"] or content_type,
        "verified": "yes",
    }
    verified["keyword_match"] = "yes" if has_document_keyword(canonical) else "no"
    return verified


def fetch_document_probe(
    url: str,
    timeout: int,
    method: str,
    byte_range: str | None = None,
) -> dict[str, object]:
    headers = {"User-Agent": USER_AGENT}
    if byte_range:
        headers["Range"] = byte_range
    request = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(4096) if method == "GET" else b""
            return {
                "url": response.geturl(),
                "status": response.status,
                "content_type": response.headers.get("content-type", ""),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(4096) if method == "GET" else b""
        return {
            "url": url,
            "status": exc.code,
            "content_type": exc.headers.get("content-type", ""),
            "body": body,
        }
    except Exception:
        return {"url": url, "status": None, "content_type": "", "body": b""}


def is_document_content_type(content_type: str) -> bool:
    content_type = content_type.split(";", 1)[0].strip().lower()
    return any(content_type.startswith(doc_type) for doc_type in DOCUMENT_CONTENT_TYPES)


def looks_like_document_bytes(content: bytes) -> bool:
    sample = content[:16]
    return any(sample.startswith(prefix) for prefix in DOCUMENT_MAGIC_PREFIXES)


def write_document_artifact(
    context: ScanContext,
    documents: list[dict[str, str]],
    filename: str = "public-documents.jsonl",
) -> dict[str, object]:
    output_path = context.config.out_dir / filename
    with output_path.open("w", encoding="utf-8") as handle:
        for item in documents:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    return artifact_info(output_path)


def collect_jsonl_lines(stdout: str, output_file: Path) -> list[str]:
    max_lines = 5000
    max_bytes = 20_000_000
    lines = [line for line in stdout.splitlines()[:max_lines] if line.strip()]
    if output_file.exists():
        bytes_read = 0
        with output_file.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                bytes_read += len(line.encode("utf-8", errors="replace"))
                if bytes_read > max_bytes or len(lines) >= max_lines:
                    break
                if line.strip():
                    lines.append(line.rstrip("\n"))
    return lines


def tool_timeout(context: ScanContext, default: int, minimum: int, multiplier: int) -> int:
    return max(minimum, min(default, context.config.timeout_seconds * multiplier))


def collect_port_banners(port_details: dict[str, list[int]]) -> dict[str, dict[str, dict[str, object]]]:
    tasks = []
    for host, ports in sorted(port_details.items()):
        for port in sorted(set(ports)):
            tasks.append((host, port))

    checks: dict[str, dict[str, dict[str, object]]] = {}
    if not tasks:
        return checks

    with ThreadPoolExecutor(max_workers=min(16, len(tasks))) as pool:
        future_map = {pool.submit(probe_port_banner, host, port): (host, port) for host, port in tasks}
        for future in as_completed(future_map):
            host, port = future_map[future]
            try:
                check = future.result()
            except Exception as exc:  # noqa: BLE001
                check = {"banner_found": False, "status": "probe_error", "error": str(exc)}
            checks.setdefault(host, {})[str(port)] = check
    return checks


def probe_port_banner(host: str, port: int, timeout: float = 1.2, max_bytes: int = 160) -> dict[str, object]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(max_bytes)
            except TimeoutError:
                data = b""
            except OSError:
                data = b""
    except OSError as exc:
        return {"banner_found": False, "status": "connect_failed", "error": str(exc)}

    banner = data.decode("utf-8", "replace").replace("\r", "\\r").replace("\n", "\\n").strip()
    if not banner:
        return {"banner_found": False, "status": "no_banner"}
    return {"banner_found": True, "status": "banner", "banner": banner[:max_bytes]}


def probe_accept_all_host(host: str, detected_ports: set[int], timeout: float = 0.6) -> dict[str, object] | None:
    ports = [port for port in CONTROL_PORTS if port not in detected_ports][:8]
    if not ports:
        return None

    open_ports = []
    for port in ports:
        if tcp_connects(host, port, timeout=timeout):
            open_ports.append(port)

    if len(open_ports) < 5:
        return None
    return {
        "control_ports_tested": ports,
        "control_ports_open": open_ports,
        "note": "Контрольные случайные порты тоже принимают TCP-connect; это похоже на accept-all/tarpit/firewall, а не на подтвержденные сервисы.",
    }


def tcp_connects(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def artifact_info(path: Path) -> dict:
    return {"path": str(path), "exists": path.exists(), "bytes": file_size(path)}


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def tail_lines(path: Path, limit: int = 20) -> list[str]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-limit:]


def parse_json_line(line: str) -> dict | None:
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        return None
    return item if isinstance(item, dict) else None


def is_owned_host(host: str | None, domain: str) -> bool:
    if not host:
        return False
    host = host.lower().strip().strip(".")
    return host == domain or host.endswith("." + domain)


def is_owned_url(url: str, domain: str) -> bool:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    return is_owned_host(host, domain)


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


def highest_severity(left: Severity, right: Severity) -> Severity:
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return right if order[right] > order[left] else left


def normalize_nuclei_fingerprint(item: dict) -> tuple[str, str, str] | None:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    template = str(item.get("template-id") or item.get("template") or "").strip().lower()
    name = str(info.get("name") or "").strip().lower()
    target = str(item.get("matched-at") or item.get("host") or "").strip().lower().rstrip("/")
    matcher = str(item.get("matcher-name") or item.get("matcher_name") or "").strip().lower()
    if not template and not name:
        return None
    title_key = name or template
    return title_key, target, matcher
