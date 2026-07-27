from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from hacker_soft.core.models import Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import http_get


SECURITY_HEADERS = {
    "strict-transport-security": "Enable HSTS with an appropriate max-age after validating HTTPS everywhere.",
    "content-security-policy": "Add a Content-Security-Policy tuned to the application.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "referrer-policy": "Set a privacy-preserving Referrer-Policy.",
    "permissions-policy": "Set a restrictive Permissions-Policy for browser features.",
}


class HttpProbeModule(ScannerModule):
    name = "http_probe"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        hosts = sorted({context.target.domain, *context.subdomains})[: context.config.max_hosts]
        urls = []
        for host in hosts:
            urls.append(f"https://{host}/")
            if context.config.active:
                urls.append(f"http://{host}/")

        with ThreadPoolExecutor(max_workers=16) as pool:
            future_map = {pool.submit(http_get, url, context.config.timeout_seconds): url for url in urls}
            for future in as_completed(future_map):
                response = future.result()
                if response.status is None:
                    continue
                context.live_hosts.add(response.url)
                context.http_services[response.url] = {
                    "status": response.status,
                    "server": response.headers.get("server"),
                    "title": extract_title(response.body_sample),
                    "headers": response.headers,
                }
                self._header_findings(response.url, response.headers, result)
                self._server_disclosure(response.url, response.headers, result)

        result.artifacts["live_count"] = len(context.live_hosts)
        return result

    def _header_findings(self, url: str, headers: dict[str, str], result: ModuleResult) -> None:
        missing = [header for header in SECURITY_HEADERS if header not in headers]
        if missing:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Не хватает стандартных браузерных security headers",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    target=url,
                    evidence={"missing": missing},
                    recommendation="Добавь недостающие security headers на edge-уровне или в приложении.",
                    explanation="Security headers - это настройки ответа сайта, которые включают дополнительные защиты в браузере.",
                    impact="Без них браузер слабее защищает пользователей от части атак вроде XSS, clickjacking и утечек referrer.",
                    fix="Добавить недостающие заголовки в приложении, nginx/caddy/traefik или CDN.",
                )
            )

    def _server_disclosure(self, url: str, headers: dict[str, str], result: ModuleResult) -> None:
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        if server or powered_by:
            result.findings.append(
                Finding(
                    module=self.name,
                    title="HTTP-заголовки раскрывают технологию или версию",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    target=url,
                    evidence={"server": server, "x-powered-by": powered_by},
                    recommendation="Убери лишнее раскрытие версий и технологий из публичных HTTP-заголовков.",
                    explanation="Сайт сообщает наружу используемые технологии или версии через HTTP-заголовки.",
                    impact="Это не взлом само по себе, но помогает атакующему быстрее подобрать известные уязвимости под ваш стек.",
                    fix="Скрыть лишние version banners и оставить только технически необходимые заголовки.",
                )
            )


def extract_title(html: str) -> str | None:
    lower = html.lower()
    start = lower.find("<title")
    if start == -1:
        return None
    start = lower.find(">", start)
    end = lower.find("</title>", start)
    if start == -1 or end == -1:
        return None
    return " ".join(html[start + 1 : end].split())[:200]
