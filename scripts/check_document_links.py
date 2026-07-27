#!/usr/bin/env python
"""Check whether URLs open and resolve to documents.

Input can be a plain text/CSV/JSONL file. The script extracts all http(s) URLs,
checks each source URL, and for HTML pages tries to find document links inside.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import html
import json
import re
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse

import httpx


URL_RE = re.compile(r"https?://[^\s<>'\")\]}]+", re.IGNORECASE)
DOC_EXTENSIONS = (
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
    ".rtf",
    ".zip",
    ".rar",
    ".7z",
)
DOC_CONTENT_TYPES = (
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
DOC_MAGIC_PREFIXES = (
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"{\\rtf",
)
DOCUMENT_HINT_WORDS = (
    "скачать",
    "документ",
    "документы",
    "файл",
    "download",
    "document",
    "pdf",
    "doc",
    "xls",
    "ppt",
)
ANTI_BOT_MARKERS = (
    "captcha",
    "verify you are human",
    "cloudflare",
    "ddos-guard",
    "access denied",
    "attention required",
    "checking your browser",
)


@dataclass
class FoundDocument:
    url: str
    source: str
    anchor_text: str = ""
    status_code: int | None = None
    content_type: str = ""
    ok: bool = False
    error: str = ""


@dataclass
class LinkCheckResult:
    source_url: str
    final_url: str = ""
    status: str = "UNKNOWN"
    status_code: int | None = None
    content_type: str = ""
    title: str = ""
    documents_found: list[FoundDocument] = field(default_factory=list)
    error: str = ""
    elapsed_ms: int = 0


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.title = ""
        self._current_href: str | None = None
        self._current_text: list[str] = []
        self._in_title = False
        self._title_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v or "" for k, v in attrs}
        if tag.lower() == "a" and attr.get("href"):
            self._current_href = attr["href"]
            self._current_text = []
        elif tag.lower() == "title":
            self._in_title = True
            self._title_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)
        if self._in_title:
            self._title_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            text = " ".join(" ".join(self._current_text).split())
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []
        elif tag.lower() == "title":
            self.title = " ".join(" ".join(self._title_text).split())
            self._in_title = False


class DomainRateLimiter:
    def __init__(self, delay_seconds: float) -> None:
        self.delay_seconds = delay_seconds
        self._last_request: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def wait(self, url: str) -> None:
        if self.delay_seconds <= 0:
            return
        domain = urlparse(url).netloc.lower()
        async with self._locks[domain]:
            now = time.monotonic()
            sleep_for = self.delay_seconds - (now - self._last_request[domain])
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._last_request[domain] = time.monotonic()


def normalize_url(raw: str) -> str:
    return raw.rstrip(".,;:")


def load_urls(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    urls = [normalize_url(match.group(0)) for match in URL_RE.finditer(text)]
    seen = set()
    unique = []
    for url in urls:
        if url not in seen:
            unique.append(url)
            seen.add(url)
    return unique


def is_document_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in DOC_EXTENSIONS)


def is_document_content_type(content_type: str) -> bool:
    ct = content_type.split(";", 1)[0].strip().lower()
    return any(ct.startswith(doc_ct) for doc_ct in DOC_CONTENT_TYPES)


def is_html_content_type(content_type: str) -> bool:
    ct = content_type.split(";", 1)[0].strip().lower()
    return ct in ("text/html", "application/xhtml+xml") or not ct


def looks_like_html_bytes(content: bytes) -> bool:
    sample = content.lstrip()[:200].lower()
    return sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def looks_like_document_bytes(content: bytes) -> bool:
    sample = content[:16]
    return any(sample.startswith(prefix) for prefix in DOC_MAGIC_PREFIXES)


def looks_like_antibot(html: str, status_code: int | None) -> bool:
    sample = html[:20000].lower()
    if status_code in (401, 403, 429):
        return any(marker in sample for marker in ANTI_BOT_MARKERS)
    return any(marker in sample for marker in ANTI_BOT_MARKERS)


def find_candidate_document_links(base_url: str, html: str, max_links: int) -> tuple[str, list[FoundDocument]]:
    parser = LinkExtractor()
    parser.feed(html)
    candidates: list[FoundDocument] = []
    seen = set()
    for href, text in parser.links:
        absolute = urljoin(base_url, href)
        lower_text = text.lower()
        lower_href = absolute.lower()
        has_doc_ext = is_document_url(absolute)
        has_hint = any(word in lower_text or word in lower_href for word in DOCUMENT_HINT_WORDS)
        if not has_doc_ext and not has_hint:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        candidates.append(FoundDocument(url=absolute, source="html_link", anchor_text=text[:300]))
        if len(candidates) >= max_links:
            break
    return parser.title, candidates


async def request_url(
    client: httpx.AsyncClient,
    limiter: DomainRateLimiter,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    await limiter.wait(url)
    return await client.request(method, url, follow_redirects=True, headers=headers)


async def fetch_document_sample(
    client: httpx.AsyncClient,
    limiter: DomainRateLimiter,
    url: str,
) -> httpx.Response:
    return await request_url(
        client,
        limiter,
        url,
        method="GET",
        headers={"Range": "bytes=0-4095"},
    )


async def probe_document(
    client: httpx.AsyncClient,
    limiter: DomainRateLimiter,
    doc: FoundDocument,
) -> FoundDocument:
    try:
        response = await request_url(client, limiter, doc.url, method="HEAD")
        if response.status_code in (405, 403) or response.status_code >= 500:
            response = await request_url(client, limiter, doc.url, method="GET")
        doc.status_code = response.status_code
        doc.content_type = response.headers.get("content-type", "")
        doc.url = str(response.url)
        if response.status_code < 400 and (
            is_document_content_type(doc.content_type) or is_document_url(str(response.url))
        ):
            sample_response = await fetch_document_sample(client, limiter, doc.url)
            doc.status_code = sample_response.status_code
            doc.content_type = sample_response.headers.get("content-type", doc.content_type)
            doc.url = str(sample_response.url)
            doc.ok = sample_response.status_code < 400 and looks_like_document_bytes(sample_response.content)
    except Exception as exc:  # noqa: BLE001 - report network/parser failures per URL.
        doc.error = repr(exc)
    return doc


async def check_one(
    client: httpx.AsyncClient,
    limiter: DomainRateLimiter,
    url: str,
    max_document_links: int,
) -> LinkCheckResult:
    started = time.monotonic()
    result = LinkCheckResult(source_url=url)
    try:
        response = await request_url(client, limiter, url, method="HEAD")
        content_type = response.headers.get("content-type", "")
        can_answer_from_head = response.status_code < 400 and (
            is_document_content_type(content_type) or is_document_url(str(response.url))
        )
        if can_answer_from_head:
            response = await fetch_document_sample(client, limiter, str(response.url))
        else:
            response = await request_url(client, limiter, url, method="GET")
        result.final_url = str(response.url)
        result.status_code = response.status_code
        result.content_type = response.headers.get("content-type", "")

        if response.status_code >= 500:
            result.status = "SERVER_ERROR"
            return result
        if response.status_code in (401, 403):
            result.status = "ACCESS_DENIED"
            return result
        if response.status_code == 429:
            result.status = "ANTI_BOT_BLOCKED"
            return result
        if response.status_code >= 400:
            result.status = "BROKEN_LINK"
            return result

        if is_document_content_type(result.content_type) or is_document_url(result.final_url):
            if not looks_like_document_bytes(response.content):
                if looks_like_html_bytes(response.content) or is_html_content_type(result.content_type):
                    html = response.text
                    if looks_like_antibot(html, response.status_code):
                        result.status = "ANTI_BOT_BLOCKED"
                    else:
                        result.status = "NOT_A_DOCUMENT"
                    return result
                result.status = "NOT_A_DOCUMENT"
                return result
            result.status = "DIRECT_DOCUMENT"
            result.documents_found.append(
                FoundDocument(
                    url=result.final_url,
                    source="direct",
                    status_code=response.status_code,
                    content_type=result.content_type,
                    ok=True,
                )
            )
            return result

        if not is_html_content_type(result.content_type):
            result.status = "NO_DOCUMENT_FOUND"
            return result

        html = response.text
        if looks_like_antibot(html, response.status_code):
            result.status = "ANTI_BOT_BLOCKED"
            return result

        title, candidates = find_candidate_document_links(result.final_url, html, max_document_links)
        result.title = title
        if not candidates:
            result.status = "NO_DOCUMENT_FOUND"
            return result

        result.documents_found = await asyncio.gather(
            *(probe_document(client, limiter, doc) for doc in candidates)
        )
        if any(doc.ok for doc in result.documents_found):
            result.status = "DOCUMENT_FOUND"
        else:
            result.status = "DOCUMENT_CANDIDATES_BROKEN"
        return result
    except Exception as exc:  # noqa: BLE001 - report network/parser failures per URL.
        result.status = "REQUEST_ERROR"
        result.error = repr(exc)
        return result
    finally:
        result.elapsed_ms = int((time.monotonic() - started) * 1000)


def csv_row(result: LinkCheckResult) -> dict[str, str | int | None]:
    ok_docs = [doc for doc in result.documents_found if doc.ok]
    return {
        "source_url": result.source_url,
        "status": result.status,
        "status_code": result.status_code,
        "final_url": result.final_url,
        "content_type": result.content_type,
        "documents_ok": len(ok_docs),
        "documents_total": len(result.documents_found),
        "first_document_url": ok_docs[0].url if ok_docs else "",
        "title": result.title,
        "error": result.error,
        "elapsed_ms": result.elapsed_ms,
    }


def csv_fieldnames() -> list[str]:
    return [
        "source_url",
        "status",
        "status_code",
        "final_url",
        "content_type",
        "documents_ok",
        "documents_total",
        "first_document_url",
        "title",
        "error",
        "elapsed_ms",
    ]


def load_completed_urls(path: Path) -> set[str]:
    if not path.exists():
        return set()
    completed = set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            source_url = data.get("source_url")
            if isinstance(source_url, str):
                completed.add(source_url)
    return completed


def load_results(path: Path) -> list[LinkCheckResult]:
    results = []
    if not path.exists():
        return results
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            documents = [FoundDocument(**doc) for doc in data.get("documents_found", [])]
            data["documents_found"] = documents
            results.append(LinkCheckResult(**data))
    return results


async def run_checks(args: argparse.Namespace) -> list[LinkCheckResult]:
    urls = load_urls(Path(args.input))
    if args.limit:
        urls = urls[: args.limit]
    jsonl_path = Path(args.out_jsonl)
    csv_path = Path(args.out_csv)
    completed_urls = load_completed_urls(jsonl_path) if args.resume else set()
    if completed_urls:
        urls = [url for url in urls if url not in completed_urls]

    timeout = httpx.Timeout(args.timeout)
    headers = {
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,*/*;q=0.8",
    }
    limiter = DomainRateLimiter(args.per_domain_delay)
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    append = args.resume and jsonl_path.exists()
    async with httpx.AsyncClient(timeout=timeout, headers=headers, limits=limits) as client:
        semaphore = asyncio.Semaphore(args.concurrency)

        async def guarded(url: str) -> LinkCheckResult:
            async with semaphore:
                return await check_one(client, limiter, url, args.max_document_links)

        tasks = [guarded(url) for url in urls]
        results = []
        with jsonl_path.open("a" if append else "w", encoding="utf-8") as jsonl_f, csv_path.open(
            "a" if append else "w", encoding="utf-8", newline=""
        ) as csv_f:
            writer = csv.DictWriter(csv_f, fieldnames=csv_fieldnames())
            if not append:
                writer.writeheader()
            for i, task in enumerate(asyncio.as_completed(tasks), start=1):
                result = await task
                results.append(result)
                jsonl_f.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
                writer.writerow(csv_row(result))
                jsonl_f.flush()
                csv_f.flush()
                if args.verbose:
                    done_total = i + len(completed_urls)
                    all_total = len(tasks) + len(completed_urls)
                    print(f"[{done_total}/{all_total}] {result.status} {result.source_url}", flush=True)
        return results


def write_jsonl(path: Path, results: Iterable[LinkCheckResult]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")


def write_csv(path: Path, results: Iterable[LinkCheckResult]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=csv_fieldnames(),
        )
        writer.writeheader()
        for result in results:
            writer.writerow(csv_row(result))


def result_document_url(result: LinkCheckResult) -> str:
    ok_docs = [doc for doc in result.documents_found if doc.ok]
    if ok_docs:
        return ok_docs[0].url
    return result.final_url or result.source_url


def write_html_report(path: Path, results: list[LinkCheckResult]) -> None:
    real_document_results = [
        result for result in results if result.status in ("DIRECT_DOCUMENT", "DOCUMENT_FOUND")
    ]
    broken_results = [result for result in results if result.status == "BROKEN_LINK"]
    other_count = len(results) - len(real_document_results) - len(broken_results)

    def ok_documents(result: LinkCheckResult) -> list[FoundDocument]:
        return [doc for doc in result.documents_found if doc.ok]

    document_rows: list[tuple[LinkCheckResult, FoundDocument]] = []
    for result in real_document_results:
        docs = ok_documents(result)
        if docs:
            document_rows.extend((result, doc) for doc in docs)
        else:
            document_rows.append(
                (
                    result,
                    FoundDocument(
                        url=result_document_url(result),
                        source="result",
                        status_code=result.status_code,
                        content_type=result.content_type,
                        ok=True,
                    ),
                )
            )

    documents_count = len(document_rows)

    def document_row(result: LinkCheckResult, doc: FoundDocument, index: int) -> str:
        status_code = doc.status_code if doc.status_code is not None else result.status_code
        content_type = doc.content_type or result.content_type
        return (
            "<tr>"
            f"<td>{index}</td>"
            f"<td><a href=\"{html.escape(doc.url, quote=True)}\" target=\"_blank\" rel=\"noopener noreferrer\">"
            f"{html.escape(doc.url)}</a></td>"
            f"<td><a href=\"{html.escape(result.source_url, quote=True)}\" target=\"_blank\" rel=\"noopener noreferrer\">"
            f"{html.escape(result.source_url)}</a></td>"
            f"<td>{html.escape(str(status_code or ''))}</td>"
            f"<td>{html.escape(content_type)}</td>"
            "</tr>"
        )

    def link_row(result: LinkCheckResult, index: int) -> str:
        url = result_document_url(result)
        return (
            "<tr>"
            f"<td>{index}</td>"
            f"<td><a href=\"{html.escape(url, quote=True)}\" target=\"_blank\" rel=\"noopener noreferrer\">"
            f"{html.escape(url)}</a></td>"
            f"<td>{html.escape(str(result.status_code or ''))}</td>"
            f"<td>{html.escape(result.content_type)}</td>"
            "</tr>"
        )

    def broken_row(result: LinkCheckResult, index: int) -> str:
        return (
            "<tr>"
            f"<td>{index}</td>"
            f"<td><a href=\"{html.escape(result.source_url, quote=True)}\" target=\"_blank\" rel=\"noopener noreferrer\">"
            f"{html.escape(result.source_url)}</a></td>"
            f"<td>{html.escape(str(result.status_code or ''))}</td>"
            f"<td>{html.escape(result.content_type)}</td>"
            "</tr>"
        )

    document_table_rows = "\n".join(
        document_row(result, doc, i) for i, (result, doc) in enumerate(document_rows, start=1)
    )
    real_rows = "\n".join(link_row(result, i) for i, result in enumerate(real_document_results, start=1))
    broken_rows = "\n".join(broken_row(result, i) for i, result in enumerate(broken_results, start=1))

    content = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Document Link Check Report</title>
  <style>
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #1f2937;
      background: #f8fafc;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px;
    }}
    h1 {{
      margin: 0 0 18px;
      font-size: 28px;
      font-weight: 700;
    }}
    h2 {{
      margin: 24px 0 12px;
      font-size: 18px;
      font-weight: 700;
    }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }}
    .metric {{
      background: #ffffff;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 14px 16px;
    }}
    .metric strong {{
      display: block;
      font-size: 26px;
      line-height: 1.2;
      margin-bottom: 4px;
    }}
    .metric span {{
      color: #64748b;
      font-size: 14px;
    }}
    details {{
      background: #ffffff;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      margin-top: 12px;
      overflow: hidden;
    }}
    summary {{
      cursor: pointer;
      padding: 14px 16px;
      font-weight: 650;
      background: #f1f5f9;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      padding: 9px 10px;
      border-top: 1px solid #e5e7eb;
      vertical-align: top;
      text-align: left;
    }}
    th {{
      color: #475569;
      background: #f8fafc;
      font-weight: 650;
    }}
    td:first-child, th:first-child {{
      width: 56px;
      color: #64748b;
    }}
    a {{
      color: #0f766e;
      overflow-wrap: anywhere;
    }}
  </style>
</head>
<body>
<main>
  <h1>Отчёт проверки ссылок на документы</h1>
  <h2>Краткая сводка отчета</h2>
  <section class="summary">
    <div class="metric"><strong>{len(results)}</strong><span>Всего проверено ссылок</span></div>
    <div class="metric"><strong>{documents_count}</strong><span>Найдено документов</span></div>
    <div class="metric"><strong>{len(real_document_results)}</strong><span>Ссылок на реальные документы</span></div>
    <div class="metric"><strong>{len(broken_results)}</strong><span>Битых ссылок</span></div>
    <div class="metric"><strong>{other_count}</strong><span>Других статусов</span></div>
  </section>

  <details open>
    <summary>Ссылки на документы ({documents_count})</summary>
    <table>
      <thead><tr><th>#</th><th>Документ</th><th>Источник</th><th>HTTP</th><th>Content-Type</th></tr></thead>
      <tbody>{document_table_rows}</tbody>
    </table>
  </details>

  <details>
    <summary>Ссылки на реальные документы ({len(real_document_results)})</summary>
    <table>
      <thead><tr><th>#</th><th>Ссылка</th><th>HTTP</th><th>Content-Type</th></tr></thead>
      <tbody>{real_rows}</tbody>
    </table>
  </details>

  <details>
    <summary>Битые ссылки ({len(broken_results)})</summary>
    <table>
      <thead><tr><th>#</th><th>Ссылка</th><th>HTTP</th><th>Content-Type</th></tr></thead>
      <tbody>{broken_rows}</tbody>
    </table>
  </details>
</main>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def print_summary(results: list[LinkCheckResult]) -> None:
    counts: dict[str, int] = defaultdict(int)
    for result in results:
        counts[result.status] += 1
    print("Summary:")
    for status, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"  {status}: {count}")
    print(f"  TOTAL: {len(results)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check URLs and resolve document links.")
    parser.add_argument("--input", required=True, help="Text/CSV/JSONL file containing URLs")
    parser.add_argument("--out-jsonl", default="link_check_results.jsonl")
    parser.add_argument("--out-csv", default="link_check_results.csv")
    parser.add_argument("--out-html", default="", help="HTML report path. Defaults to out-jsonl with .html suffix")
    parser.add_argument("--limit", type=int, default=0, help="Check only first N unique URLs")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--per-domain-delay", type=float, default=1.0)
    parser.add_argument("--max-document-links", type=int, default=20)
    parser.add_argument("--resume", action="store_true", help="Append results and skip URLs already present in JSONL")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (compatible; DocumentLinkChecker/0.1; +https://example.local)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    results = asyncio.run(run_checks(args))
    report_results = load_results(Path(args.out_jsonl))
    html_path = Path(args.out_html) if args.out_html else Path(args.out_jsonl).with_suffix(".html")
    write_html_report(html_path, report_results)
    print_summary(report_results)
    print(f"JSONL: {args.out_jsonl}")
    print(f"CSV:   {args.out_csv}")
    print(f"HTML:  {html_path}")


if __name__ == "__main__":
    main()
