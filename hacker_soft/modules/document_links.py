from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

from hacker_soft.core.models import Category, Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import USER_AGENT
from hacker_soft.modules.projectdiscovery import (
    add_document_candidate,
    document_verification_details,
    empty_document_summary,
    iter_link_candidates,
    summarize_documents,
    verify_document_summary,
    write_document_artifact,
)


SITEMAP_URL_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
ROBOTS_SITEMAP_RE = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


class DocumentLinksModule(ScannerModule):
    name = "document_links"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        input_urls = collect_document_check_urls(context)
        if not input_urls:
            result.artifacts["document_link_input_count"] = 0
            return result

        input_path = context.config.out_dir / "document-link-input.txt"
        candidates_path = context.config.out_dir / "document-link-candidates.jsonl"
        input_path.write_text("\n".join(input_urls) + "\n", encoding="utf-8")

        candidate_summary = collect_document_candidates(input_urls, context)
        write_jsonl(candidates_path, candidate_summary.get("documents", []))
        verified_summary = verify_document_summary(candidate_summary, context)
        result.artifacts["document_verification"] = document_verification_details(verified_summary)
        result.artifacts["document_link_input"] = artifact_info(input_path)
        result.artifacts["document_link_input_count"] = len(input_urls)
        result.artifacts["document_link_candidates"] = artifact_info(candidates_path)
        result.artifacts["document_link_candidate_count"] = candidate_summary.get("total", 0)

        if not verified_summary.get("total"):
            return result

        result.artifacts["public_documents"] = {
            "total": verified_summary["total"],
            "by_type": verified_summary["by_type"],
            "by_host": verified_summary["by_host"],
            "keyword_matches": verified_summary["keyword_matches"],
            "sample": verified_summary["sample"],
            "documents": verified_summary["documents"],
            "full_list": write_document_artifact(context, verified_summary["documents"], filename="document-link-public-documents.jsonl"),
            "checked_total": verified_summary.get("checked_total", candidate_summary.get("total", 0)),
            "rejected_total": verified_summary.get("rejected_total", 0),
            "source": "fresh_document_link_check",
            **document_verification_details(verified_summary),
        }
        result.findings.append(
            Finding(
                module=self.name,
                title="Публичные документы проверены в рамках текущего отчета",
                severity=Severity.INFO,
                category=Category.INVENTORY,
                confidence=Confidence.HIGH,
                target=context.target.domain,
                evidence={
                    "total": verified_summary["total"],
                    "by_type": verified_summary["by_type"],
                    "candidate_count": candidate_summary.get("total", 0),
                    "input_urls": len(input_urls),
                },
                recommendation="Разобрать подтвержденные документы и убрать из публикации файлы, которые не должны быть доступны публично.",
                explanation="Сервис собрал URL для текущего домена, нашел ссылки на документы в HTML и подтвердил документы сетевой проверкой.",
                impact="В публичных документах могут быть метаданные, договоры, заявки, контакты, внутренние названия и иная чувствительная информация.",
                fix="Сверить публикации с владельцами разделов, закрыть лишние файлы и очищать метаданные перед публикацией.",
            )
        )
        return result


def collect_document_check_urls(context: ScanContext) -> list[str]:
    domain = context.target.domain
    seeds = {
        f"https://{domain}/",
        f"http://{domain}/",
        f"https://www.{domain}/",
        f"http://www.{domain}/",
        *context.live_hosts,
        *context.endpoints,
    }
    sitemap_urls = collect_sitemap_urls(domain, context.config.timeout_seconds)
    limit = max(500, context.config.max_hosts * context.config.max_urls_per_host)
    return sorted(url for url in {*seeds, *sitemap_urls} if is_owned_http_url(url, domain))[:limit]


def collect_sitemap_urls(domain: str, timeout: int) -> set[str]:
    sitemap_roots = {
        f"https://{domain}/sitemap.xml",
        f"https://www.{domain}/sitemap.xml",
        f"http://{domain}/sitemap.xml",
        f"http://www.{domain}/sitemap.xml",
    }
    for robots_url in (f"https://{domain}/robots.txt", f"https://www.{domain}/robots.txt"):
        robots = fetch_text(robots_url, timeout)
        sitemap_roots.update(ROBOTS_SITEMAP_RE.findall(robots))

    seen_sitemaps: set[str] = set()
    urls: set[str] = set()
    queue = list(sitemap_roots)
    while queue and len(seen_sitemaps) < 50 and len(urls) < 5000:
        sitemap_url = queue.pop(0)
        if sitemap_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap_url)
        text = fetch_text(sitemap_url, timeout)
        if not text:
            continue
        locs = parse_sitemap_locs(text)
        for loc in locs:
            if loc.lower().endswith(".xml") and "sitemap" in loc.lower():
                queue.append(loc)
            else:
                urls.add(loc)
    return urls


def parse_sitemap_locs(text: str) -> list[str]:
    try:
        root = ET.fromstring(text.encode("utf-8"))
        locs = []
        for node in root.iter():
            if node.tag.lower().endswith("loc") and node.text:
                locs.append(node.text.strip())
        return locs
    except ET.ParseError:
        return [match.strip() for match in SITEMAP_URL_RE.findall(text)]


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=max(6, timeout)) as response:
            return response.read(5_000_000).decode("utf-8", errors="replace")
    except Exception:
        return ""


def collect_document_candidates(input_urls: list[str], context: ScanContext) -> dict[str, object]:
    documents: dict[str, dict[str, str]] = {}
    if not input_urls:
        return empty_document_summary()
    timeout = max(6, context.config.timeout_seconds)
    max_workers = max(1, min(10, len(input_urls)))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(collect_candidates_from_url, url, context.target.domain, timeout) for url in input_urls]
        for future in as_completed(futures):
            for item in future.result().values():
                documents.setdefault(item["url"], item)
    return summarize_documents(documents)


def collect_candidates_from_url(url: str, domain: str, timeout: int) -> dict[str, dict[str, str]]:
    documents: dict[str, dict[str, str]] = {}
    add_document_candidate(documents, url, domain)
    text = fetch_text(url, timeout)
    if not text:
        return documents
    base_url = url if is_owned_http_url(url, domain) else f"https://{domain}/"
    for candidate in iter_link_candidates(text):
        normalized = str(candidate or "").strip()
        if not normalized or normalized.startswith(("mailto:", "javascript:", "tel:")):
            continue
        add_document_candidate(documents, urljoin(base_url, normalized), domain)
    return documents


def write_jsonl(path: Path, rows: object) -> None:
    items = rows if isinstance(rows, list) else []
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def is_owned_http_url(url: str, domain: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower().strip(".")
    domain = domain.lower().strip(".")
    return parsed.scheme in {"http", "https"} and (host == domain or host.endswith("." + domain))


def artifact_info(path: Path) -> dict[str, object]:
    return {"path": str(path), "bytes": path.stat().st_size if path.exists() else 0}
