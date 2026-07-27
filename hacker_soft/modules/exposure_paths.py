from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urlparse

from hacker_soft.core.models import Category, Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import HttpResponse, http_get


SENSITIVE_PATHS = [
    ("/.env", "env"),
    ("/.git/config", "git_config"),
    ("/config.php", "php_source"),
    ("/config.json", "json_config"),
    ("/backup.zip", "archive"),
    ("/backup.sql", "sql_dump"),
    ("/db.sql", "sql_dump"),
    ("/dump.sql", "sql_dump"),
    ("/phpinfo.php", "phpinfo"),
    ("/server-status", "server_status"),
    ("/.well-known/security.txt", "security_txt"),
]

SECRET_MARKERS = [
    "aws_access_key_id",
    "aws_secret_access_key",
    "database_url",
    "db_password",
    "private_key",
    "secret_key",
    "api_key",
]

LOGIN_URL_MARKERS = (
    "logon.aspx",
    "/auth/",
    "/login",
    "/signin",
    "/sign-in",
    "/sso",
    "/adfs",
    "/oauth2/authorize",
    "/account/login",
    "/owa/",
    "/idp/",
)

LOGIN_BODY_MARKERS = (
    'type="password"',
    "type='password'",
    "j_security_check",
    "__requestverificationtoken",
    "authenticity_token",
)

ARCHIVE_MAGIC = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ",
)

SQL_MARKERS = (
    "create table",
    "insert into",
    "drop table if exists",
    "mysql dump",
    "mysqldump",
    "pg_dump",
    "-- dumping data",
)

ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=", re.MULTILINE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
HEX_RUN_RE = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)
DIGIT_RUN_RE = re.compile(r"\d+")
WHITESPACE_RE = re.compile(r"\s+")

BASELINE_PROBES = 2
LENGTH_TOLERANCE = 0.05
CATCH_ALL_REPORT_THRESHOLD = 3


@dataclass
class Baseline:
    """How a host answers a request for a path that certainly does not exist."""

    statuses: set[int] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    lengths: list[int] = field(default_factory=list)
    titles: set[str] = field(default_factory=set)
    tokens: list[str] = field(default_factory=list)
    final_paths: set[str] = field(default_factory=set)

    @property
    def catch_all(self) -> bool:
        return bool(self.statuses & {200, 206})

    def as_evidence(self) -> dict[str, object]:
        return {
            "statuses": sorted(self.statuses),
            "catch_all": self.catch_all,
            "body_lengths": self.lengths,
            "titles": sorted(title for title in self.titles if title),
        }


class ExposurePathsModule(ScannerModule):
    name = "exposure_paths"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.active:
            result.artifacts["skipped"] = "требуется --active"
            return result

        base_hosts = sorted({context.target.domain, *context.subdomains})[: min(context.config.max_hosts, 50)]
        paths = SENSITIVE_PATHS[: context.config.max_urls_per_host]
        origins = [(scheme, host) for host in base_hosts for scheme in ("https", "http")]
        timeout = context.config.timeout_seconds

        baselines = self._collect_baselines(origins, timeout)
        checks = self._probe_paths(origins, paths, baselines, timeout)

        rejected = [check for check in checks if not check["accepted"]]
        accepted = [check for check in checks if check["accepted"]]

        for check in accepted:
            result.findings.append(build_finding(self.name, check))

        self._report_catch_all_hosts(result, rejected)

        result.artifacts["checked_urls"] = len(checks)
        result.artifacts["confirmed"] = len(accepted)
        result.artifacts["rejected"] = len(rejected)
        result.artifacts["rejected_reasons"] = dict(Counter(check["reason"] for check in rejected).most_common())
        result.artifacts["catch_all_origins"] = sorted(
            f"{scheme}://{host}" for (scheme, host), baseline in baselines.items() if baseline.catch_all
        )
        security_txt = sorted(check["url"] for check in checks if check["kind"] == "security_txt" and check["accepted"])
        if security_txt:
            result.artifacts["security_txt_published"] = security_txt
        return result

    def _collect_baselines(
        self,
        origins: list[tuple[str, str]],
        timeout: int,
    ) -> dict[tuple[str, str], Baseline]:
        baselines: dict[tuple[str, str], Baseline] = {}
        if not origins:
            return baselines
        with ThreadPoolExecutor(max_workers=min(16, len(origins))) as pool:
            future_map = {pool.submit(build_baseline, scheme, host, timeout): (scheme, host) for scheme, host in origins}
            for future in as_completed(future_map):
                origin = future_map[future]
                try:
                    baselines[origin] = future.result()
                except Exception:  # noqa: BLE001 - a missing baseline must not stop the scan.
                    baselines[origin] = Baseline()
        return baselines

    def _probe_paths(
        self,
        origins: list[tuple[str, str]],
        paths: list[tuple[str, str]],
        baselines: dict[tuple[str, str], Baseline],
        timeout: int,
    ) -> list[dict[str, object]]:
        tasks = [(scheme, host, path, kind) for scheme, host in origins for path, kind in paths]
        if not tasks:
            return []

        checks: list[dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            future_map = {
                pool.submit(http_get, f"{scheme}://{host}{path}", timeout, 16384): (scheme, host, path, kind)
                for scheme, host, path, kind in tasks
            }
            for future in as_completed(future_map):
                scheme, host, path, kind = future_map[future]
                try:
                    response = future.result()
                except Exception as exc:  # noqa: BLE001 - keep scanning other paths.
                    checks.append(
                        {
                            "url": f"{scheme}://{host}{path}",
                            "host": host,
                            "path": path,
                            "kind": kind,
                            "accepted": False,
                            "reason": "request_failed",
                            "detail": str(exc)[:200],
                        }
                    )
                    continue
                checks.append(classify_response(response, host, path, kind, baselines.get((scheme, host), Baseline())))
        return checks

    def _report_catch_all_hosts(self, result: ModuleResult, rejected: list[dict[str, object]]) -> None:
        by_host: dict[str, list[str]] = {}
        for check in rejected:
            if check["reason"] in {"baseline_match", "login_page", "redirected"}:
                by_host.setdefault(str(check["host"]), []).append(str(check["path"]))
        noisy = {host: sorted(set(paths)) for host, paths in by_host.items() if len(set(paths)) >= CATCH_ALL_REPORT_THRESHOLD}
        if not noisy:
            return
        result.artifacts["filtered_generic_responses"] = noisy
        result.findings.append(
            Finding(
                module=self.name,
                title="Хосты отдают одинаковый ответ на любой путь (ложные срабатывания отфильтрованы)",
                severity=Severity.INFO,
                category=Category.DIAGNOSTIC,
                confidence=Confidence.HIGH,
                target=", ".join(sorted(noisy)[:5]),
                evidence={"hosts": noisy, "filtered_checks": len(rejected)},
                recommendation="Отдельных действий не требуется: это пояснение, почему проверенные чувствительные пути не попали в находки.",
                explanation=(
                    "На этих хостах запрос несуществующего файла возвращает ту же страницу, что и запрос чувствительного пути: "
                    "обычно это форма входа, SSO-редирект или единая страница-заглушка."
                ),
                impact="Такие ответы не означают, что файл существует, поэтому они исключены из находок, чтобы не завышать риск.",
                fix="Ничего чинить не нужно. Если файл на таком хосте действительно важен, проверить его вручную с авторизацией.",
            )
        )


def build_baseline(scheme: str, host: str, timeout: int) -> Baseline:
    baseline = Baseline()
    for index in range(BASELINE_PROBES):
        token = secrets.token_hex(12)
        suffix = ".sql" if index else ""
        path = f"/{token}{suffix}"
        response = http_get(f"{scheme}://{host}{path}", timeout, 16384)
        if response.status is None:
            continue
        baseline.statuses.add(response.status)
        baseline.tokens.append(token)
        baseline.hashes.add(body_fingerprint(response.body_sample, token))
        baseline.lengths.append(len(response.body_sample))
        baseline.titles.add(extract_title(response.body_sample))
        baseline.final_paths.add(response_path(response.url))
    return baseline


def classify_response(
    response: HttpResponse,
    host: str,
    path: str,
    kind: str,
    baseline: Baseline,
) -> dict[str, object]:
    check: dict[str, object] = {
        "url": response.url or f"https://{host}{path}",
        "host": host,
        "path": path,
        "kind": kind,
        "status": response.status,
        "content_type": (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower(),
        "accepted": False,
        "reason": "",
        "detail": "",
        "markers": [],
    }

    if response.status not in {200, 206}:
        check["reason"] = "status"
        return check

    final_path = response_path(response.url)
    if final_path and not paths_match(final_path, path):
        check["reason"] = "redirected"
        check["detail"] = f"итоговый путь {final_path} не совпадает с запрошенным {path}"
        return check

    if looks_like_login(response):
        check["reason"] = "login_page"
        check["detail"] = "ответ выглядит как форма входа или страница аутентификации"
        return check

    if matches_baseline(response, baseline):
        check["reason"] = "baseline_match"
        check["detail"] = "тот же ответ, что и на заведомо несуществующий путь"
        check["baseline"] = baseline.as_evidence()
        return check

    signature_ok, signature_note = matches_content_signature(kind, response)
    if not signature_ok:
        check["reason"] = "content_mismatch"
        check["detail"] = signature_note
        return check

    check["accepted"] = True
    check["reason"] = "verified"
    check["detail"] = signature_note
    check["markers"] = find_secret_markers(response.body_sample)
    check["baseline"] = baseline.as_evidence()
    return check


def matches_baseline(response: HttpResponse, baseline: Baseline) -> bool:
    if not baseline.statuses:
        return False
    if response.status not in baseline.statuses:
        return False

    fingerprints = {body_fingerprint(response.body_sample, token) for token in baseline.tokens}
    fingerprints.add(body_fingerprint(response.body_sample, ""))
    if fingerprints & baseline.hashes:
        return True

    if not baseline.catch_all:
        return False

    title = extract_title(response.body_sample)
    if title and title in baseline.titles:
        return True

    length = len(response.body_sample)
    return any(
        abs(length - baseline_length) <= max(64, baseline_length * LENGTH_TOLERANCE)
        for baseline_length in baseline.lengths
    )


def matches_content_signature(kind: str, response: HttpResponse) -> tuple[bool, str]:
    body = response.body_sample
    lower = body.lower()
    content_type = (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    is_html = content_type.startswith("text/html") or "<html" in lower[:2048] or "<!doctype html" in lower[:2048]

    if kind == "archive":
        if response.body_bytes.startswith(ARCHIVE_MAGIC):
            return True, "первые байты соответствуют формату архива"
        if content_type in {"application/zip", "application/x-zip-compressed", "application/x-rar-compressed", "application/gzip", "application/x-7z-compressed"}:
            return True, f"сервер отдает архив с content-type {content_type}"
        return False, f"вместо архива отдан {content_type or 'неизвестный тип'} без сигнатуры архива"

    if kind == "sql_dump":
        if is_html:
            return False, "вместо SQL-дампа отдана HTML-страница"
        matched = [marker for marker in SQL_MARKERS if marker in lower]
        if matched:
            return True, f"в теле найдены признаки SQL-дампа: {', '.join(matched[:3])}"
        return False, "тело ответа не похоже на SQL-дамп"

    if kind == "env":
        if is_html:
            return False, "вместо .env отдана HTML-страница"
        if ENV_LINE_RE.search(body):
            return True, "тело содержит строки вида KEY=VALUE, характерные для .env"
        return False, "тело ответа не похоже на .env"

    if kind == "git_config":
        if "[core]" in lower and "repositoryformatversion" in lower:
            return True, "тело содержит структуру git config"
        return False, "тело ответа не похоже на git config"

    if kind == "phpinfo":
        if "phpinfo()" in lower or "php version" in lower:
            return True, "страница содержит вывод phpinfo()"
        return False, "страница не содержит вывод phpinfo()"

    if kind == "server_status":
        if "apache server status" in lower or "server uptime" in lower or "nginx status" in lower:
            return True, "страница содержит вывод server-status"
        return False, "страница не содержит вывод server-status"

    if kind == "php_source":
        if "<?php" in lower:
            return True, "сервер отдает исходный код PHP вместо его выполнения"
        return False, "исходный код PHP не раскрыт (файл выполняется или отсутствует)"

    if kind == "json_config":
        if is_html:
            return False, "вместо JSON отдана HTML-страница"
        try:
            parsed = json.loads(body)
        except ValueError:
            return False, "тело ответа не является валидным JSON"
        if isinstance(parsed, dict) and parsed:
            return True, "сервер отдает JSON-конфигурацию"
        return False, "JSON не содержит конфигурационных полей"

    if kind == "security_txt":
        if "contact:" in lower:
            return True, "опубликован корректный security.txt"
        return False, "файл не похож на security.txt"

    return False, "неизвестный тип проверки"


def build_finding(module: str, check: dict[str, object]) -> Finding:
    markers = list(check.get("markers") or [])
    category = Category.ISSUE
    if markers:
        severity = Severity.HIGH
        confidence = Confidence.HIGH
        title = "Публично доступен чувствительный файл с признаками секретов"
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.HIGH
        title = "Публично доступен чувствительный файл"

    if check["kind"] == "security_txt":
        severity = Severity.INFO
        confidence = Confidence.HIGH
        title = "Опубликован security.txt"
        category = Category.INVENTORY

    return Finding(
        module=module,
        title=title,
        severity=severity,
        confidence=confidence,
        category=category,
        target=str(check["url"]),
        evidence={
            "status": check.get("status"),
            "content_type": check.get("content_type"),
            "verdict": check.get("detail"),
            "markers": markers,
            "baseline": check.get("baseline"),
        },
        recommendation="Закрой публичный доступ, ротируй засвеченные секреты при наличии и убери старые артефакты.",
        explanation=(
            "Путь доступен без авторизации, и содержимое ответа подтверждает ожидаемый тип файла: "
            "это не страница входа и не универсальная заглушка."
        ),
        impact="Если внутри есть секреты или дампы, их может скачать любой, кто знает URL.",
        fix="Закрыть доступ, удалить файл из публичной директории и заменить секреты, если они могли утечь.",
    )


def find_secret_markers(body: str) -> list[str]:
    lower = body.lower()
    return [marker for marker in SECRET_MARKERS if marker in lower]


def looks_like_login(response: HttpResponse) -> bool:
    url = (response.url or "").lower()
    if any(marker in url for marker in LOGIN_URL_MARKERS):
        return True
    body = response.body_sample.lower()
    return any(marker in body for marker in LOGIN_BODY_MARKERS)


def response_path(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except ValueError:
        return ""


def paths_match(final_path: str, requested_path: str) -> bool:
    return final_path.rstrip("/").lower() == requested_path.rstrip("/").lower()


def extract_title(body: str) -> str:
    match = TITLE_RE.search(body)
    if not match:
        return ""
    return WHITESPACE_RE.sub(" ", match.group(1)).strip().lower()[:200]


def body_fingerprint(body: str, token: str) -> str:
    text = body.lower()
    if token:
        text = text.replace(token.lower(), "")
    text = HEX_RUN_RE.sub("", text)
    text = DIGIT_RUN_RE.sub("", text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
