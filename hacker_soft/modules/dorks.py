from __future__ import annotations

import base64
from html.parser import HTMLParser
import json
import time
import urllib.parse

from hacker_soft.core.models import Category, Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import http_get
from hacker_soft.modules.projectdiscovery import (
    document_verification_details,
    has_document_keyword,
    summarize_documents as summarize_public_documents,
    verify_document_summary,
    write_document_artifact,
)


DORK_TEMPLATES = [
    ("PDF-документы", "site:{domain} filetype:pdf"),
    ("Word-документы DOC", "site:{domain} filetype:doc"),
    ("Word-документы DOCX", "site:{domain} filetype:docx"),
    ("Excel-документы XLS", "site:{domain} filetype:xls"),
    ("Excel-документы XLSX", "site:{domain} filetype:xlsx"),
    ("Презентации PPT", "site:{domain} filetype:ppt"),
    ("Презентации PPTX", "site:{domain} filetype:pptx"),
    ("RTF-документы", "site:{domain} filetype:rtf"),
    ("Открытые env/config-файлы", 'site:{domain} (ext:env OR ext:yml OR ext:yaml OR ext:ini OR ext:conf)'),
    ("Открытые dotenv и секреты", 'site:{domain} (filetype:env OR inurl:.env OR intext:DB_PASSWORD OR intext:API_KEY)'),
    ("Конфигурации приложений", 'site:{domain} (filetype:json OR filetype:xml OR filetype:toml OR filetype:properties)'),
    ("Kubernetes и Docker-конфиги", 'site:{domain} (filetype:kubeconfig OR filetype:dockerfile OR filename:docker-compose.yml OR intext:kubeconfig)'),
    ("Индексируемые директории", 'site:{domain} intitle:"index of"'),
    ("Дампы баз данных", 'site:{domain} (ext:sql OR ext:sqlite OR ext:db OR ext:dump)'),
    ("Дампы и экспорты данных", 'site:{domain} (filetype:csv OR filetype:tsv OR filetype:json OR filetype:xml) (password OR token OR secret OR email)'),
    ("Архивы и бэкапы", 'site:{domain} (ext:zip OR ext:tar OR ext:gz OR ext:7z OR ext:bak OR ext:old)'),
    ("Расширенные бэкапы", 'site:{domain} (filetype:rar OR filetype:tgz OR filetype:bz2 OR filetype:backup OR filetype:swp)'),
    ("Логи", 'site:{domain} (ext:log OR inurl:logs)'),
    ("Отчеты об ошибках и stack traces", 'site:{domain} (intext:"Traceback" OR intext:"stack trace" OR intext:"Fatal error" OR intext:"Exception")'),
    ("Админки и страницы входа", 'site:{domain} (inurl:admin OR inurl:login OR intitle:admin)'),
    ("Панели управления", 'site:{domain} (intitle:"dashboard" OR intitle:"control panel" OR inurl:dashboard OR inurl:cpanel)'),
    ("Публичные документы", 'site:{domain} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:doc OR filetype:xls OR filetype:csv)'),
    ("Презентации и офисные документы", 'site:{domain} (filetype:ppt OR filetype:pptx OR filetype:rtf OR filetype:odt OR filetype:ods OR filetype:odp)'),
    ("Текстовые документы и заметки", 'site:{domain} (filetype:txt OR filetype:md OR filetype:log)'),
    ("Документы с чувствительными словами", 'site:{domain} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx) (confidential OR internal OR private OR restricted)'),
    ("Финансовые и договорные документы", 'site:{domain} (filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx) (invoice OR contract OR budget OR payroll OR salary)'),
    ("Русскоязычные документы", 'site:{domain} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx) (конфиденциально OR договор OR счет OR зарплата OR пароль)'),
    ("Пароли и учетные данные в индексе", 'site:{domain} (password OR passwd OR credentials OR token OR secret OR "api key")'),
    ("Засвет .git", 'site:{domain} inurl:.git'),
    ("Засвет служебных VCS-файлов", 'site:{domain} (inurl:.svn OR inurl:.hg OR inurl:.bzr OR inurl:.git/config)'),
    ("Открытые CI/CD артефакты", 'site:{domain} (inurl:.github OR inurl:.gitlab-ci OR filetype:yml "CI" OR filetype:yaml "CI")'),
    ("Облачные бакеты", '"{domain}" (site:s3.amazonaws.com OR site:storage.googleapis.com OR site:blob.core.windows.net)'),
    ("Расширенный поиск бакетов", '"{domain}" (site:amazonaws.com OR site:digitaloceanspaces.com OR site:storage.yandexcloud.net OR site:backblazeb2.com)'),
    ("Упоминания на GitHub", 'site:github.com "{domain}"'),
    ("Упоминания в GitLab/Bitbucket", '"{domain}" (site:gitlab.com OR site:bitbucket.org)'),
    ("Секреты в публичном коде", '"{domain}" (site:github.com OR site:gitlab.com OR site:bitbucket.org) (password OR token OR secret OR api_key OR apikey)'),
    ("Упоминания в paste-сервисах", '"{domain}" (site:pastebin.com OR site:ghostbin.co OR site:rentry.co)'),
    ("Упоминания в документации и тикетах", '"{domain}" (site:docs.google.com OR site:drive.google.com OR site:notion.site OR site:atlassian.net OR site:trello.com)'),
    ("Индексируемые API", 'site:{domain} (inurl:api OR inurl:swagger OR inurl:openapi OR filetype:json "swagger")'),
    ("Swagger/OpenAPI", 'site:{domain} (intitle:"Swagger UI" OR inurl:swagger-ui OR inurl:api-docs OR inurl:openapi.json)'),
    ("GraphQL", 'site:{domain} (inurl:graphql OR intitle:"GraphQL Playground" OR intext:"GraphiQL")'),
    ("Публичные backups по имени домена", '"{domain}" (backup OR dump OR archive OR database OR db_backup)'),
]

SEARCH_ENGINES = {
    "google": {
        "url": "https://www.google.com/search?q={query}&num={count}&start={offset}",
        "offset_step": 10,
    },
    "bing": {
        "url": "https://www.bing.com/search?q={query}&count={count}&first={offset}",
        "offset_start": 1,
        "offset_step": 10,
    },
    "duckduckgo": {
        "url": "https://duckduckgo.com/html/?q={query}&s={offset}",
        "offset_step": 30,
    },
    "duckduckgo_lite": {
        "url": "https://lite.duckduckgo.com/lite/?q={query}",
        "offset_step": 0,
    },
    "yahoo": {
        "url": "https://search.yahoo.com/search?p={query}&b={offset}",
        "offset_start": 1,
        "offset_step": 10,
    },
}
SEARCH_ENGINE_ORDER = ("duckduckgo_lite", "yahoo", "google", "duckduckgo", "bing")

SEARCH_ENGINE_HOSTS = {
    "bing.com",
    "www.bing.com",
    "duckduckgo.com",
    "www.duckduckgo.com",
    "lite.duckduckgo.com",
    "google.com",
    "www.google.com",
    "search.yahoo.com",
    "yahoo.com",
    "www.yahoo.com",
}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp", "csv"}


class DorkBuilderModule(ScannerModule):
    name = "dork_builder"
    passive = True

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        domain = context.target.domain
        dorks = []
        for title, template in DORK_TEMPLATES:
            query = template.format(domain=domain)
            dorks.append(
                {
                    "title": title,
                    "query": query,
                    "google": "https://www.google.com/search?q=" + urllib.parse.quote_plus(query),
                    "bing": "https://www.bing.com/search?q=" + urllib.parse.quote_plus(query),
                    "duckduckgo": "https://duckduckgo.com/html/?q=" + urllib.parse.quote_plus(query),
                }
            )
        result.artifacts["dorks"] = dorks
        dork_artifacts = write_dork_artifacts(context, dorks)
        result.artifacts.update(dork_artifacts)
        search_results, search_errors, search_summary = self._search_dorks(context, dorks)
        indexed_documents, index_errors = search_indexed_documents(context, domain)
        if search_summary:
            result.artifacts["auto_dork_summary"] = search_summary
            unverified = [item for item in search_summary if item.get("status") == "unverified"]
            if unverified:
                result.artifacts["unverified_dorks"] = [
                    {
                        "title": item["title"],
                        "query": item["query"],
                        "google": item["google"],
                        "bing": item["bing"],
                        "duckduckgo": item["duckduckgo"],
                        "blocked_engines": sorted(set(item.get("blocked_engines") or [])),
                        "skipped_engines": sorted(set(item.get("skipped_engines") or [])),
                    }
                    for item in unverified
                ]
                result.artifacts["unverified_dork_count"] = len(unverified)
        if search_results:
            result.artifacts["search_result_count"] = len(search_results)
            result.artifacts["search_results"] = search_results
            result.artifacts["search_results_jsonl"] = write_search_results_artifact(context, search_results)
            result.findings.append(
                Finding(
                    module=self.name,
                    title="Поисковики вернули результаты по dorks",
                    severity=Severity.INFO,
                    category=Category.INVENTORY,
                    confidence=Confidence.MEDIUM,
                    target=domain,
                    evidence={"count": len(search_results), "sample": search_results[:10]},
                    recommendation="Проверь найденные URL вручную: часть результатов может быть устаревшей или нерелевантной.",
                    explanation="Автоматический поиск нашел страницы, которые совпали с dork-запросами по домену.",
                    impact="В выдаче могут оказаться документы, бэкапы, конфиги, старые админки или упоминания в сторонних сервисах.",
                    fix="Убрать чувствительные материалы из публичного доступа, закрыть индексацию и запросить переобход/удаление из поисковиков.",
                )
            )
        document_results = merge_document_results(extract_document_results(search_results), indexed_documents)
        if document_results:
            result.artifacts["document_search_results"] = summarize_document_results(context, document_results)
            public_document_summary = build_public_document_summary(document_results)
            verified_summary = verify_document_summary(public_document_summary, context)
            result.artifacts["document_verification"] = document_verification_details(verified_summary)
            if verified_summary.get("total"):
                result.artifacts["public_documents"] = {
                    "total": verified_summary["total"],
                    "by_type": verified_summary["by_type"],
                    "by_host": verified_summary["by_host"],
                    "keyword_matches": verified_summary["keyword_matches"],
                    "sample": verified_summary["sample"],
                    "documents": verified_summary["documents"],
                    "full_list": write_document_artifact(
                        context,
                        verified_summary["documents"],
                        filename="indexed-public-documents.jsonl",
                    ),
                    "checked_total": verified_summary.get("checked_total", verified_summary["total"]),
                    "rejected_total": verified_summary.get("rejected_total", 0),
                    "source": "current_index_search",
                    **document_verification_details(verified_summary),
                }
        if index_errors:
            result.artifacts["index_search_errors"] = index_errors[:20]
        if search_errors:
            result.artifacts["search_errors"] = search_errors[:20]
        result.findings.append(
            Finding(
                module=self.name,
                title="Нужна ручная проверка Google/Bing dorks",
                severity=Severity.INFO,
                category=Category.DIAGNOSTIC,
                confidence=Confidence.HIGH,
                target=domain,
                evidence={
                    "dork_count": len(dorks),
                    "auto_search_enabled": context.config.auto_dork_search,
                    "unverified_dork_count": result.artifacts.get("unverified_dork_count", 0),
                    "sample": dorks[:8],
                },
                recommendation="Проверь сгенерированные dorks и автоматическую выдачу на индексируемые секреты, документы, бэкапы, админки и утечки.",
                explanation="Это набор поисковых запросов, которые помогают найти, что поисковики уже знают о домене.",
                impact="Если в индексе есть конфиги, документы, логи, бэкапы или админки, их может найти любой человек.",
                fix="Открыть ссылки из доказательств, проверить выдачу и убрать из публичного доступа все чувствительное.",
            )
        )
        return result

    def _search_dorks(
        self,
        context: ScanContext,
        dorks: list[dict[str, str]],
    ) -> tuple[list[dict[str, str]], list[str], list[dict[str, object]]]:
        if not context.config.auto_dork_search:
            return [], [], []

        domain = context.target.domain
        query_limit = max(0, min(context.config.max_dork_queries, len(dorks)))
        result_limit = max(1, context.config.max_dork_results)
        search_results: list[dict[str, str]] = []
        errors: list[str] = []
        seen_urls: set[str] = set()
        summary_by_title: dict[str, dict[str, object]] = {
            dork["title"]: {
                "title": dork["title"],
                "query": dork["query"],
                "google": dork["google"],
                "bing": dork["bing"],
                "duckduckgo": dork["duckduckgo"],
                "result_count": 0,
                "errors": [],
                "answered_engines": [],
                "blocked_engines": [],
                "skipped_engines": [],
                "status": "unverified",
            }
            for dork in dorks[:query_limit]
        }

        engine_errors: dict[str, int] = {}
        engine_disabled: set[str] = set()
        for dork in dorks[:query_limit]:
            for engine in SEARCH_ENGINE_ORDER:
                if engine in engine_disabled:
                    summary_by_title[dork["title"]]["skipped_engines"].append(engine)
                    continue
                engine_config = SEARCH_ENGINES[engine]
                try:
                    parsed_results, error = search_one_dork(context, dork, engine, engine_config, domain, result_limit)
                except Exception as exc:  # noqa: BLE001
                    parsed_results, error = [], str(exc)

                summary = summary_by_title[dork["title"]]
                if error:
                    message = f"{engine}: dork '{dork['title']}' не выполнен: {error}"
                    errors.append(message)
                    summary["errors"].append(message)
                    summary["blocked_engines"].append(engine)
                    engine_errors[engine] = engine_errors.get(engine, 0) + 1
                    if is_search_block_or_timeout(error) and engine_errors[engine] >= 3:
                        engine_disabled.add(engine)
                        stop_message = (
                            f"{engine}: автопоиск временно остановлен после серии блокировок/таймаутов, "
                            "чтобы не усиливать антибот-ограничения"
                        )
                        errors.append(stop_message)
                    continue

                summary["answered_engines"].append(engine)
                new_count = 0
                for item in parsed_results:
                    normalized_url = normalize_result_url(item["url"])
                    if not normalized_url or normalized_url in seen_urls:
                        continue
                    seen_urls.add(normalized_url)
                    owned_url = is_owned_url(normalized_url, domain)
                    if owned_url:
                        context.endpoints.add(normalized_url)
                    search_results.append(
                        {
                            "engine": engine,
                            "dork_title": dork["title"],
                            "query": dork["query"],
                            "title": item["title"],
                            "url": normalized_url,
                            "owned_url": owned_url,
                        }
                    )
                    new_count += 1
                summary["result_count"] = int(summary["result_count"]) + new_count

        for summary in summary_by_title.values():
            summary["status"] = dork_status(summary)
        return search_results, errors, list(summary_by_title.values())


def dork_status(summary: dict[str, object]) -> str:
    """Distinguish "checked and empty" from "never actually checked" because of antibot limits."""
    if int(summary.get("result_count") or 0) > 0:
        return "found"
    if summary.get("answered_engines"):
        return "empty"
    return "unverified"


def search_one_dork(
    context: ScanContext,
    dork: dict[str, str],
    engine: str,
    engine_config: dict[str, object],
    domain: str,
    result_limit: int,
) -> tuple[list[dict[str, str]], str | None]:
    encoded_query = urllib.parse.quote_plus(dork["query"])
    page_size = min(10, max(1, result_limit))
    offset_start = int(engine_config.get("offset_start") or 0)
    offset_step = int(engine_config.get("offset_step") or 0)
    started = time.monotonic()
    all_results: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    errors: list[str] = []
    if context.logger:
        context.logger.info(f"external request start: {engine} dork={dork['title']!r} timeout={context.config.timeout_seconds}s")
    page = 0
    while len(all_results) < result_limit:
        offset = offset_start + (page * offset_step)
        url = str(engine_config["url"]).format(query=encoded_query, count=page_size, offset=offset)
        response = http_get(url, timeout=context.config.timeout_seconds, max_bytes=900_000)
        if response.error and response.status is None:
            errors.append(response.error)
            break
        parsed_results = parse_search_results(response.body_sample, domain, result_limit - len(all_results))
        if not parsed_results:
            diagnostic = diagnose_empty_search_response(response.body_sample, response.status, engine)
            if diagnostic:
                errors.append(diagnostic)
            break
        new_results = 0
        for item in parsed_results:
            normalized_url = normalize_result_url(item["url"])
            if not normalized_url or normalized_url in seen_urls:
                continue
            seen_urls.add(normalized_url)
            all_results.append({"url": normalized_url, "title": item["title"]})
            new_results += 1
            if len(all_results) >= result_limit:
                break
        if new_results == 0 or offset_step <= 0:
            break
        page += 1
    elapsed = time.monotonic() - started
    if errors and not all_results:
        if context.logger:
            context.logger.error(
                f"external request failed: {engine} dork={dork['title']!r} "
                f"elapsed={elapsed:.1f}s error={errors[0]}"
            )
        return [], errors[0]
    if context.logger:
        context.logger.info(
            f"external request end: {engine} dork={dork['title']!r} "
            f"elapsed={elapsed:.1f}s rows={len(all_results)}"
        )
    return all_results, None


def is_search_block_or_timeout(error: str) -> bool:
    text = error.lower()
    return any(
        marker in text
        for marker in (
            "антибот",
            "captcha",
            "429",
            "403",
            "timed out",
            "timeout",
            "handshake operation timed out",
            "read operation timed out",
        )
    )


class SearchResultParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        attrs_dict = {name: value or "" for name, value in attrs}
        href = attrs_dict.get("href")
        if href:
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._current_href:
            return
        title = " ".join(" ".join(self._current_text).split())
        self.links.append({"url": self._current_href, "title": title})
        self._current_href = None
        self._current_text = []


def parse_search_results(html: str, domain: str, limit: int) -> list[dict[str, str]]:
    parser = SearchResultParser()
    parser.feed(html)
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for link in parser.links:
        url = normalize_result_url(link["url"])
        if not url or url in seen or is_search_engine_url(url):
            continue
        title = link["title"] or url
        decoded = urllib.parse.unquote_plus(url)
        haystack = f"{decoded} {title}".lower()
        if domain.lower() not in haystack:
            continue
        seen.add(url)
        results.append({"url": url, "title": title[:240]})
        if len(results) >= limit:
            break
    return results


def diagnose_empty_search_response(html: str, status: int | None, engine: str) -> str | None:
    text = html.lower()
    if status in {403, 429}:
        return f"{engine}: поисковик ограничил автоматический запрос, HTTP {status}"
    if any(marker in text for marker in ("captcha", "unusual traffic", "verify you are human", "detected unusual")):
        return f"{engine}: поисковик показал антибот/капчу"
    if any(marker in text for marker in ("no results found", "ничего не найдено", "did not match any documents")):
        return None
    if not html.strip():
        return f"{engine}: пустой ответ поисковика"
    return None


def extract_document_results(search_results: list[dict[str, str]]) -> list[dict[str, str]]:
    documents = {}
    for item in search_results:
        url = normalize_result_url(str(item.get("url", "")))
        extension = document_extension(url)
        if not extension and not is_document_search_result(item, url):
            continue
        documents.setdefault(
            canonical_document_url(url),
            {
                "url": canonical_document_url(url),
                "extension": extension or "unknown",
                "engine": str(item.get("engine", "")),
                "dork_title": str(item.get("dork_title", "")),
                "title": str(item.get("title", "")),
            },
        )
    return [documents[url] for url in sorted(documents)]


def search_indexed_documents(context: ScanContext, domain: str) -> tuple[list[dict[str, str]], list[str]]:
    if not context.config.auto_dork_search:
        return [], []
    errors: list[str] = []
    indexes = fetch_common_crawl_indexes(context, errors)
    if not indexes:
        return [], errors

    per_extension_limit = max(100, min(5000, context.config.max_dork_results * 100))
    documents: dict[str, dict[str, str]] = {}
    for index in indexes[:1]:
        index_id = str(index.get("id") or "")
        cdx_api = str(index.get("cdx-api") or "")
        if not index_id or not cdx_api:
            continue
        for extension in DOCUMENT_EXTENSIONS:
            url = (
                f"{cdx_api}?url=*.{urllib.parse.quote(domain)}/*.{extension}"
                f"&output=json&fl=url,status,mime,timestamp&filter=status:200&collapse=urlkey&limit={per_extension_limit}"
            )
            response = http_get(url, timeout=max(12, context.config.timeout_seconds), max_bytes=5_000_000)
            if response.error and response.status is None:
                errors.append(f"commoncrawl {index_id} {extension}: {response.error}")
                continue
            for line in response.body_sample.splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                doc_url = normalize_result_url(str(item.get("url") or ""))
                if not doc_url or not is_owned_url(doc_url, domain):
                    continue
                doc_extension = document_extension(doc_url)
                if doc_extension != extension:
                    continue
                canonical = canonical_document_url(doc_url)
                documents.setdefault(
                    canonical,
                    {
                        "url": canonical,
                        "extension": doc_extension,
                        "engine": "commoncrawl",
                        "dork_title": f"Common Crawl .{extension}",
                        "title": item.get("mime") or index_id,
                    },
                )
    return [documents[url] for url in sorted(documents)], errors


def fetch_common_crawl_indexes(context: ScanContext, errors: list[str]) -> list[dict[str, object]]:
    response = http_get("https://index.commoncrawl.org/collinfo.json", timeout=max(12, context.config.timeout_seconds), max_bytes=300_000)
    if response.error and response.status is None:
        errors.append(f"commoncrawl index list: {response.error}")
        return []
    try:
        indexes = json.loads(response.body_sample)
    except json.JSONDecodeError as exc:
        errors.append(f"commoncrawl index list: invalid json: {exc}")
        return []
    if not isinstance(indexes, list):
        errors.append("commoncrawl index list: unexpected response")
        return []
    return [item for item in indexes if isinstance(item, dict)]


def merge_document_results(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    documents = {}
    for group in groups:
        for item in group:
            url = normalize_result_url(str(item.get("url", "")))
            extension = document_extension(url) or str(item.get("extension") or "")
            if not extension:
                continue
            canonical = canonical_document_url(url)
            documents.setdefault(canonical, {**item, "url": canonical, "extension": extension})
    return [documents[url] for url in sorted(documents)]


def build_public_document_summary(documents: list[dict[str, str]]) -> dict[str, object]:
    public_documents: dict[str, dict[str, str]] = {}
    for item in documents:
        url = str(item.get("url") or "")
        extension = document_extension(url) or str(item.get("extension") or "")
        if not extension:
            continue
        canonical = canonical_document_url(url)
        host = urllib.parse.urlparse(canonical).netloc
        public_documents.setdefault(
            canonical,
            {
                **item,
                "url": canonical,
                "extension": extension,
                "host": host,
                "keyword_match": "yes" if has_document_keyword(canonical) else "no",
            },
        )
    return summarize_public_documents(public_documents)


def summarize_document_results(context: ScanContext, documents: list[dict[str, str]]) -> dict[str, object]:
    by_type: dict[str, int] = {}
    for item in documents:
        extension = item["extension"]
        by_type[extension] = by_type.get(extension, 0) + 1
    output_path = context.config.out_dir / "dork-document-results.jsonl"
    output_path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in documents) + "\n",
        encoding="utf-8",
    )
    return {
        "total": len(documents),
        "by_type": dict(sorted(by_type.items(), key=lambda item: (-item[1], item[0]))),
        "sample": documents[:20],
        "artifact": artifact_info(output_path),
    }


def document_extension(url: str) -> str | None:
    if not url:
        return None
    path = urllib.parse.urlparse(url).path.lower()
    for extension in DOCUMENT_EXTENSIONS:
        if path.endswith("." + extension):
            return extension
    return None


def canonical_document_url(url: str) -> str:
    return urllib.parse.urldefrag(url)[0]


def is_document_search_result(item: dict[str, str], url: str) -> bool:
    query = str(item.get("query") or "").lower()
    dork_title = str(item.get("dork_title") or "").lower()
    title = str(item.get("title") or "").lower()
    document_query = any(
        marker in query
        for extension in DOCUMENT_EXTENSIONS
        for marker in (f"filetype:{extension}", f"ext:{extension}")
    )
    text_hint = any(
        marker in f"{dork_title} {title} {url.lower()}"
        for marker in ("документ", "document", "download", "attachment", "скачать")
    )
    return document_query or text_hint


def write_dork_artifacts(context: ScanContext, dorks: list[dict[str, str]]) -> dict[str, dict[str, object]]:
    out_dir = context.config.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    google_path = out_dir / "google-dorks.txt"
    links_path = out_dir / "dork-links.md"

    google_path.write_text("\n".join(item["query"] for item in dorks) + "\n", encoding="utf-8")
    lines = [f"# Dork links: {context.target.domain}", ""]
    for item in dorks:
        lines.extend(
            [
                f"## {item['title']}",
                "",
                f"```text\n{item['query']}\n```",
                "",
                f"- Google: {item['google']}",
                f"- Bing: {item['bing']}",
                f"- DuckDuckGo: {item['duckduckgo']}",
                "",
            ]
        )
    links_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {
        "google_dorks_txt": artifact_info(google_path),
        "dork_links_markdown": artifact_info(links_path),
    }


def write_search_results_artifact(context: ScanContext, search_results: list[dict[str, str]]) -> dict[str, object]:
    output_path = context.config.out_dir / "dork-search-results.jsonl"
    output_path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in search_results) + "\n",
        encoding="utf-8",
    )
    return artifact_info(output_path)


def artifact_info(path) -> dict[str, object]:
    return {"path": str(path), "exists": path.exists(), "bytes": path.stat().st_size if path.exists() else 0}


def normalize_result_url(url: str) -> str:
    if not url:
        return ""
    if url.startswith("//"):
        url = "https:" + url
    if url.startswith("/"):
        parsed_relative = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed_relative.query)
        for key in ("uddg", "u", "url", "q", "RU"):
            if query.get(key):
                return normalize_result_url(decode_redirect_url(query[key][0]))
        return ""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    query = urllib.parse.parse_qs(parsed.query)
    for key in ("uddg", "u", "url", "q", "RU"):
        if is_search_engine_host(parsed.netloc) and query.get(key):
            return normalize_result_url(decode_redirect_url(query[key][0]))
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path, "", parsed.query, ""))


def decode_redirect_url(value: str) -> str:
    value = urllib.parse.unquote_plus(value)
    if value.startswith(("http://", "https://")):
        return value
    if value.startswith("a1"):
        payload = value[2:]
        try:
            padding = "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload + padding).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - malformed search redirects are ignored later.
            return value
        if decoded.startswith(("http://", "https://")):
            return decoded
    return value


def is_search_engine_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return is_search_engine_host(parsed.netloc)


def is_search_engine_host(host: str) -> bool:
    host = host.lower()
    return host in SEARCH_ENGINE_HOSTS or any(host.endswith("." + item) for item in SEARCH_ENGINE_HOSTS)


def is_owned_url(url: str, domain: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    return host == domain or host.endswith("." + domain)
