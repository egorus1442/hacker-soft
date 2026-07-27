from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import http_get


SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/config.php",
    "/config.json",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/server-status",
    "/.well-known/security.txt",
]

SECRET_MARKERS = [
    "aws_access_key_id",
    "aws_secret_access_key",
    "database_url",
    "db_password",
    "private_key",
    "secret_key",
    "api_key",
    "[core]",
]


class ExposurePathsModule(ScannerModule):
    name = "exposure_paths"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.active:
            result.artifacts["skipped"] = "требуется --active"
            return result

        base_hosts = sorted({context.target.domain, *context.subdomains})[: min(context.config.max_hosts, 50)]
        urls = []
        for host in base_hosts:
            for scheme in ["https", "http"]:
                for path in SENSITIVE_PATHS[: context.config.max_urls_per_host]:
                    urls.append(f"{scheme}://{host}{path}")

        with ThreadPoolExecutor(max_workers=16) as pool:
            future_map = {
                pool.submit(http_get, url, context.config.timeout_seconds, 16384): url
                for url in urls
            }
            for future in as_completed(future_map):
                response = future.result()
                if response.status not in {200, 206}:
                    continue
                body_lower = response.body_sample.lower()
                markers = [marker for marker in SECRET_MARKERS if marker in body_lower]
                if markers or is_interesting_path(response.url):
                    severity = Severity.HIGH if markers else Severity.MEDIUM
                    result.findings.append(
                        Finding(
                            module=self.name,
                            title="Потенциально чувствительный публичный путь доступен",
                            severity=severity,
                            confidence=Confidence.MEDIUM,
                            target=response.url,
                            evidence={
                                "status": response.status,
                                "content_type": response.headers.get("content-type"),
                                "markers": markers,
                            },
                            recommendation="Закрой публичный доступ, ротируй засвеченные секреты при наличии и убери старые артефакты.",
                            explanation="Публично доступен путь, который часто содержит конфиги, дампы, debug-информацию или бэкапы.",
                            impact="Если внутри есть секреты или дампы, их может скачать любой, кто знает URL.",
                            fix="Закрыть доступ, удалить файл из публичной директории и заменить секреты, если они могли утечь.",
                        )
                    )
        return result


def is_interesting_path(url: str) -> bool:
    return any(
        token in url.lower()
        for token in ["/.env", "/.git/config", "backup", "dump", "phpinfo", "server-status"]
    )
