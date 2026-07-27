from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule


COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    2376,
    3000,
    3306,
    3389,
    5000,
    5432,
    5601,
    5900,
    6379,
    8000,
    8080,
    8443,
    9000,
    9200,
    9300,
    11211,
    27017,
]

RISKY_PORTS = {
    21: "наружу открыт FTP",
    1433: "наружу открыт MSSQL",
    1521: "наружу открыт Oracle Database",
    2049: "наружу открыт NFS",
    2375: "может быть открыт Docker API",
    2376: "может быть открыт Docker API",
    3306: "наружу открыт MySQL",
    3389: "наружу открыт RDP",
    5432: "наружу открыт PostgreSQL",
    5601: "может быть открыта Kibana",
    5900: "наружу открыт VNC",
    6379: "наружу открыт Redis",
    9200: "может быть открыт Elasticsearch",
    9300: "может быть открыт Elasticsearch transport",
    11211: "наружу открыт Memcached",
    27017: "наружу открыт MongoDB",
}


class PortScanModule(ScannerModule):
    name = "port_scan"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.active:
            result.artifacts["skipped"] = "требуется --active"
            return result

        hosts = sorted({context.target.domain, *context.subdomains})[: min(context.config.max_hosts, 100)]
        jobs = [(host, port) for host in hosts for port in COMMON_PORTS]
        open_ports: dict[str, list[int]] = {}

        with ThreadPoolExecutor(max_workers=64) as pool:
            future_map = {
                pool.submit(is_open, host, port, min(context.config.timeout_seconds, 3)): (host, port)
                for host, port in jobs
            }
            for future in as_completed(future_map):
                host, port = future_map[future]
                if future.result():
                    open_ports.setdefault(host, []).append(port)

        for host, ports in sorted(open_ports.items()):
            context.open_ports.setdefault(host, set()).update(ports)
            risky = sorted(port for port in ports if port in RISKY_PORTS)
            if risky:
                result.findings.append(
                    Finding(
                        module=self.name,
                        title="Потенциально рискованный сервис открыт в интернет",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        target=host,
                        evidence={"risky_ports": {str(port): RISKY_PORTS[port] for port in risky}},
                        recommendation="Закрой административные и data-сервисы через VPN, приватную сеть или firewall allowlist.",
                        explanation="Найден сервис, который обычно не должен быть доступен всем из интернета.",
                        impact="Если это база данных, админка или удаленный доступ, ошибка настройки может привести к компрометации.",
                        fix="Закрыть порт firewall-ом, оставить доступ только через VPN/private network или allowlist.",
                    )
                )
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Найдены открытые TCP-порты",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    target=host,
                    evidence={"ports": sorted(ports)},
                    recommendation="Подтверди владельца каждого открытого сервиса, порядок обновления и мониторинг.",
                    explanation="У хоста есть открытые TCP-порты, то есть сервисы доступны из интернета.",
                    impact="Каждый открытый сервис - это часть поверхности атаки, которую нужно обновлять и мониторить.",
                    fix="Проверить, что каждый порт действительно нужен, имеет владельца и защищен.",
                )
            )

        result.artifacts["open_ports"] = {host: sorted(ports) for host, ports in open_ports.items()}
        return result


def is_open(host: str, port: int, timeout: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
