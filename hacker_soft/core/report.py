from __future__ import annotations

import json
import re
from html import escape
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, unquote, urlparse, urlunparse

from .models import Finding, ModuleResult, ScanContext, Severity


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def flatten_findings(results: Iterable[ModuleResult]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        findings.extend(result.findings)
    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.title))


def finding_to_dict(finding: Finding) -> dict:
    data = asdict(finding)
    data["severity"] = finding.severity.value
    data["confidence"] = finding.confidence.value
    return data


def write_reports(context: ScanContext, results: list[ModuleResult]) -> dict[str, Path]:
    out_dir = context.config.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = flatten_findings(results)
    summary = Counter(f.severity.value for f in findings)

    payload = {
        "target": asdict(context.target),
        "started_at": context.started_at.isoformat(),
        "config": {
            "profile": context.config.profile,
            "active": context.config.active,
            "with_tools": context.config.with_tools,
            "heavy_tools": context.config.heavy_tools,
            "auto_dork_search": context.config.auto_dork_search,
            "max_dork_queries": context.config.max_dork_queries,
            "max_dork_results": context.config.max_dork_results,
            "max_hosts": context.config.max_hosts,
        },
        "summary": dict(summary),
        "client_overview": build_client_overview(context, results, findings, summary),
        "assets": {
            "subdomains": sorted(context.subdomains),
            "live_hosts": sorted(context.live_hosts),
            "ips": sorted(context.ips),
            "endpoints": sorted(context.endpoints),
            "open_ports": {host: sorted(ports) for host, ports in context.open_ports.items()},
            "dns_records": context.dns_records,
            "http_services": context.http_services,
        },
        "log_file": str(context.config.out_dir / "scan.log"),
        "results": [
            {
                "module": result.module,
                "findings": [finding_to_dict(f) for f in result.findings],
                "artifacts": result.artifacts,
                "errors": result.errors,
            }
            for result in results
        ],
    }

    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    md_path = out_dir / "report.md"
    md_path.write_text(render_markdown(context, results, findings, summary), encoding="utf-8")

    html_path = out_dir / "report.html"
    html_path.write_text(render_html(context, results, findings, summary), encoding="utf-8")

    return {"json": json_path, "markdown": md_path, "html": html_path}


def build_client_overview(
    context: ScanContext,
    results: list[ModuleResult],
    findings: list[Finding],
    summary: Counter,
) -> dict[str, object]:
    if summary.get("critical", 0):
        level = "critical"
        title = "Есть критичные риски, лучше заняться ими сразу"
        message = "Сканер увидел признаки проблем, которые могут дать прямой доступ к сервисам или данным."
    elif summary.get("high", 0):
        level = "high"
        title = "Есть высокие риски, нужен быстрый разбор"
        message = "Найдены проблемы, которые заметно повышают вероятность атаки или утечки."
    elif summary.get("medium", 0):
        level = "medium"
        title = "Критичных сигналов нет, но есть важные настройки"
        message = "Основные риски выглядят управляемыми, однако часть защитных настроек стоит довести до нормы."
    elif summary.get("low", 0) or summary.get("info", 0):
        level = "low"
        title = "Срочных проблем не видно, есть улучшения гигиены"
        message = "Сканер не нашел критичных сигналов, но показал места, где можно уменьшить поверхность атаки."
    else:
        level = "clean"
        title = "Явных находок нет"
        message = "Автоматическая проверка не увидела заметных проблем на доступной извне поверхности."

    priority_items = []
    for finding in findings[:3]:
        priority_items.append(
            f"{severity_label(finding.severity.value)}: {finding.title} ({finding.target})"
        )
    if not priority_items:
        priority_items.append("Критичных или приоритетных находок в текущем скане нет.")

    return {
        "level": level,
        "title": title,
        "message": message,
        "priority_items": priority_items,
    }


def render_markdown(
    context: ScanContext,
    results: list[ModuleResult],
    findings: list[Finding],
    summary: Counter,
) -> str:
    overview = build_client_overview(context, results, findings, summary)
    document_summary = get_public_documents_summary(results, context.config.out_dir / "public-documents-merged.jsonl")
    lines = [
        f"# Отчет по внешней безопасности: {context.target.domain}",
        "",
        "## Краткая сводка для клиента",
        "",
        f"**Итог:** {overview['title']}. {overview['message']}",
        "",
        "### Что нашли",
        "",
        f"- Всего находок: `{len(findings)}`",
        f"- Критично: `{summary.get('critical', 0)}`",
        f"- Высоко: `{summary.get('high', 0)}`",
        f"- Средне: `{summary.get('medium', 0)}`",
        f"- Низко/инфо: `{summary.get('low', 0) + summary.get('info', 0)}`",
        "",
        "### Что проверено",
        "",
        f"- Поддомены: `{len(context.subdomains)}`",
        f"- Живые HTTP(S)-сервисы: `{len(context.live_hosts)}`",
        f"- Endpoints: `{len(context.endpoints)}`",
        f"- Публичные документы: `{document_summary.get('total', 0)}`",
        f"- IP-адреса: `{len(context.ips)}`",
        f"- Хосты с открытыми портами: `{len(context.open_ports)}`",
        "",
        "### Что важно прямо сейчас",
        "",
    ]
    for item in overview["priority_items"]:
        lines.append(f"- {item}")
    lines.extend(["", "Больше читай в отчете."])
    lines.extend(
        [
            "",
            "## Техническая сводка",
            "",
        ]
    )
    lines.extend(
        [
            f"- Профиль: `{context.config.profile}`",
            f"- Активные проверки: `{yes_no(context.config.active)}`",
            f"- Внешние CLI-инструменты: `{yes_no(context.config.with_tools)}`",
            f"- Тяжелые workflow-инструменты: `{yes_no(context.config.heavy_tools)}`",
            f"- Автопоиск по dorks: `{yes_no(context.config.auto_dork_search)}`",
            "",
        ]
    )
    if summary:
        for severity in ["critical", "high", "medium", "low", "info"]:
            lines.append(f"- {severity_label(severity)}: `{summary.get(severity, 0)}`")
    else:
        lines.append("- Находок нет.")
    if document_summary.get("total"):
        lines.extend(["", "## Публичные документы", ""])
        lines.append(f"- Всего: `{document_summary.get('total', 0)}`")
        lines.append(f"- С чувствительными словами в названии/пути: `{document_summary.get('keyword_matches', 0)}`")
        by_type = document_summary.get("by_type") or {}
        if by_type:
            lines.append(f"- По типам: `{', '.join(f'{key}: {value}' for key, value in by_type.items())}`")
        full_list = ((document_summary.get("full_list") or {}) if isinstance(document_summary.get("full_list"), dict) else {})
        if full_list.get("path"):
            lines.append(f"- Полный список: `{full_list['path']}`")
        source_groups = document_summary.get("source_groups") if isinstance(document_summary.get("source_groups"), dict) else {}
        site_documents = source_groups.get("site") if isinstance(source_groups.get("site"), list) else []
        dork_documents = source_groups.get("dorks") if isinstance(source_groups.get("dorks"), list) else []
        lines.extend(["", f"Документы со страниц сайта ({len(site_documents)}):"])
        if site_documents:
            for item in site_documents:
                if isinstance(item, dict) and item.get("url"):
                    lines.append(f"- {item['url']}")
        else:
            lines.append("- Нет")
        lines.extend(["", f"Документы из dorks ({len(dork_documents)}):"])
        if dork_documents:
            for item in dork_documents:
                if isinstance(item, dict) and item.get("url"):
                    lines.append(f"- [DORK] {item['url']}")
        else:
            lines.append("- Нет")
        lines.extend(["", "Все документы вместе:"])
        for item in document_summary.get("documents", []):
            if isinstance(item, dict) and item.get("url"):
                lines.append(f"- {item['url']}")

    dork_result = next((result for result in results if result.module == "dork_builder"), None)
    if dork_result:
        lines.extend(["", "## Google Dorking", ""])
        dork_errors = collect_dork_errors(dork_result)
        auto_summary = dork_result.artifacts.get("auto_dork_summary") if dork_result.artifacts else []
        if isinstance(auto_summary, list) and auto_summary:
            checked_count = len(auto_summary)
            found_count = sum(1 for item in auto_summary if isinstance(item, dict) and int(item.get("result_count") or 0) > 0)
            lines.append(f"- Автопроверка: проверено `{checked_count}`, с результатами `{found_count}`")
        else:
            lines.append("- Автопроверка: нет данных или выключена")
        if dork_errors:
            summary_info = summarize_dork_errors(dork_errors)
            source_text = ", ".join(f"{source}: {count}" for source, count in summary_info["sources"].items())
            reason_text = ", ".join(summary_info["reasons"]) or "ограничения внешних источников"
            lines.append(f"- Статус: частично ограничен внешними источниками ({reason_text})")
            if source_text:
                lines.append(f"- Источники с ограничениями: `{source_text}`")
        else:
            lines.append("- Статус: технических ограничений автодоркинга не зафиксировано")
    lines.extend(["", "## Приоритетные находки", ""])

    for finding in findings:
        guide = finding_guide(finding)
        lines.extend(
            [
                f"### [{finding.severity.value.upper()}] {finding.title}",
                "",
                f"- Модуль: `{finding.module}`",
                f"- Цель: `{finding.target}`",
                f"- Уверенность: `{finding.confidence.value}`",
            ]
        )
        lines.extend(["", f"Что это: {finding.explanation or guide['explanation']}"])
        lines.extend(["", f"Чем грозит: {finding.impact or guide['impact']}"])
        if finding.evidence:
            evidence = json.dumps(finding.evidence, ensure_ascii=False, indent=2)
            lines.extend(["- Доказательства:", "", "```json", evidence, "```"])
        lines.extend(["", f"Что сделать: {finding.fix or finding.recommendation or guide['fix']}"])
        if finding.references:
            lines.extend(["", "Ссылки:"])
            for ref in finding.references:
                lines.append(f"- {ref}")
        lines.append("")

    lines.extend(["## Ошибки модулей", ""])
    any_errors = False
    for result in results:
        if result.module == "dork_builder":
            continue
        for error in result.errors:
            any_errors = True
            lines.append(f"- `{result.module}`: {error}")
    if not any_errors:
        lines.append("- Нет")

    return "\n".join(lines).rstrip() + "\n"


def render_html(
    context: ScanContext,
    results: list[ModuleResult],
    findings: list[Finding],
    summary: Counter,
) -> str:
    overview = build_client_overview(context, results, findings, summary)
    priority_items_html = "\n".join(f"<li>{escape(item)}</li>" for item in overview["priority_items"])
    cards = "\n".join(render_finding_card(finding) for finding in findings)
    if not cards:
        cards = '<section class="empty">Находок нет. Это не гарантия отсутствия проблем, но явных сигналов модульный скан не увидел.</section>'

    errors_html = render_errors_html(results)
    has_errors = has_non_dork_errors(results)
    errors_note = (
        "Это не найденные уязвимости, а технические проблемы во время сбора данных: таймауты, недоступные внешние сервисы "
        "или отсутствующие инструменты. Если здесь есть записи, часть отчета могла получиться неполной."
        if has_errors
        else "Все модули завершились без технических ошибок."
    )

    subdomains = sorted(context.subdomains)
    subdomain_html = "\n".join(f"<li>{escape(host)}</li>" for host in subdomains) or "<li>Нет данных</li>"
    live_hosts = sorted(context.live_hosts)
    live_html = "\n".join(f'<li><a href="{escape(link_href(url))}">{escape(url)}</a></li>' for url in live_hosts) or "<li>Нет данных</li>"
    ips = sorted(context.ips)
    ips_html = "\n".join(f"<li>{escape(ip)}</li>" for ip in ips) or "<li>Нет данных</li>"
    endpoints = sorted(context.endpoints)
    endpoints_html = "\n".join(f'<li><a href="{escape(link_href(url))}">{escape(url)}</a></li>' for url in endpoints) or "<li>Нет данных</li>"
    ports_html = render_ports(context.open_ports)
    subdomain_panel = render_data_panel(f"Поддомены ({len(subdomains)})", subdomain_html, len(subdomains))
    live_panel = render_data_panel(f"Живые HTTP(S)-сервисы ({len(live_hosts)})", live_html, len(live_hosts))
    ips_panel = render_data_panel(f"IP-адреса ({len(ips)})", ips_html, len(ips))
    ports_panel = render_data_panel("Открытые порты", ports_html, len(context.open_ports))
    endpoints_panel = render_data_panel(f"Endpoints ({len(endpoints)})", endpoints_html, len(endpoints), wide=True)
    documents_html = render_documents_html(context, results)
    dork_html = render_dork_html(results)
    artifact_html = render_artifacts_html(results)

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Отчет по безопасности: {escape(context.target.domain)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #151922;
      --muted: #657084;
      --line: #dfe4eb;
      --critical: #8f1231;
      --high: #c22b22;
      --medium: #aa6400;
      --low: #267348;
      --info: #315b9d;
      --soft: #eef3f8;
      --good: #1f7a55;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 28px 18px 48px; }}
    header {{ padding: 18px 0 22px; border-bottom: 1px solid var(--line); }}
    h1 {{ margin: 0 0 8px; font-size: clamp(28px, 5vw, 48px); line-height: 1.05; letter-spacing: 0; }}
    h2 {{ margin: 30px 0 14px; font-size: 22px; }}
    h3 {{ margin: 0 0 12px; font-size: 18px; }}
    .muted {{ color: var(--muted); }}
    .client-summary {{
      margin: 18px 0;
    }}
    .verdict, .quick-panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(20, 25, 35, .04);
    }}
    .verdict {{ padding: 18px; border-left: 8px solid var(--info); }}
    .verdict.critical {{ border-left-color: var(--critical); }}
    .verdict.high {{ border-left-color: var(--high); }}
    .verdict.medium {{ border-left-color: var(--medium); }}
    .verdict.low {{ border-left-color: var(--low); }}
    .verdict.info {{ border-left-color: var(--info); }}
    .verdict.clean {{ border-left-color: var(--good); }}
    .eyebrow {{ margin: 0 0 6px; color: var(--muted); font-size: 13px; font-weight: 700; text-transform: uppercase; }}
    .verdict-title {{ margin: 0 0 8px; font-size: 26px; line-height: 1.15; }}
    .verdict-message {{ margin: 0 0 14px; color: var(--muted); }}
    .verdict h3 {{ margin-top: 18px; }}
    .read-more {{ margin: 14px 0 0; color: var(--muted); font-weight: 700; }}
    .quick-panel {{ padding: 16px; }}
    .quick-panel h2 {{ margin: 0 0 10px; font-size: 18px; }}
    .summary-blocks {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 12px 0 20px; }}
    .summary-block {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }}
    .summary-block b {{ display: block; font-size: 22px; }}
    .summary-block span {{ color: var(--muted); font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; margin-top: 18px; }}
    .stat, .card, .empty, .intro {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(20, 25, 35, .04);
    }}
    .intro {{ padding: 16px; margin: 18px 0 8px; }}
    .intro p {{ margin: 0 0 10px; }}
    .intro p:last-child {{ margin-bottom: 0; }}
    .stat {{ padding: 14px; }}
    .stat b {{ display: block; font-size: 24px; }}
    .stat span {{ color: var(--muted); font-size: 13px; }}
    .cards {{ display: grid; gap: 12px; }}
    .card {{ padding: 16px; border-left: 6px solid var(--info); overflow: hidden; }}
    .card.critical {{ border-left-color: var(--critical); }}
    .card.high {{ border-left-color: var(--high); }}
    .card.medium {{ border-left-color: var(--medium); }}
    .card.low {{ border-left-color: var(--low); }}
    .card.info {{ border-left-color: var(--info); }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }}
    .pill {{ border: 1px solid var(--line); border-radius: 999px; padding: 3px 8px; font-size: 12px; color: var(--muted); background: #fbfcfd; }}
    .sev {{ color: #fff; border: 0; }}
    .sev.critical {{ background: var(--critical); }}
    .sev.high {{ background: var(--high); }}
    .sev.medium {{ background: var(--medium); }}
    .sev.low {{ background: var(--low); }}
    .sev.info {{ background: var(--info); }}
    pre {{
      overflow-x: auto;
      padding: 12px;
      border-radius: 8px;
      background: #10141d;
      color: #edf2f7;
      font-size: 13px;
    }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .columns {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
    .wide {{ grid-column: 1 / -1; }}
    .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; min-width: 0; }}
    .collapsible {{ margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; background: #fbfcfd; }}
    .collapsible > summary {{ cursor: pointer; padding: 10px 12px; color: var(--text); font-weight: 700; }}
    .collapsible > summary::marker {{ color: var(--muted); }}
    .collapsible-body {{ padding: 0 12px 12px; }}
    .collapsible-body pre {{ margin: 0; }}
    .panel details.collapsible {{ margin-top: 0; }}
    .table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    .table th, .table td {{ border-bottom: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }}
    .table th {{ color: var(--muted); font-weight: 700; }}
    .document-toolbar {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; margin: 14px 0; flex-wrap: wrap; }}
    .document-list {{ display: grid; gap: 8px; }}
    .document-card {{ display: grid; grid-template-columns: 46px minmax(0, 1fr) auto; gap: 10px; align-items: center; border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #fbfcfd; }}
    .document-card[hidden] {{ display: none; }}
    .doc-icon {{ width: 38px; height: 38px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800; color: #fff; background: var(--info); letter-spacing: 0; }}
    .doc-icon.pdf {{ background: #b42318; }}
    .doc-icon.doc, .doc-icon.docx, .doc-icon.rtf, .doc-icon.odt {{ background: #2159a8; }}
    .doc-icon.xls, .doc-icon.xlsx, .doc-icon.csv, .doc-icon.ods {{ background: #1f7a55; }}
    .doc-icon.ppt, .doc-icon.pptx, .doc-icon.odp {{ background: #b75519; }}
    .document-main {{ min-width: 0; }}
    .document-title {{ display: block; font-weight: 700; color: var(--text); text-decoration: none; overflow-wrap: anywhere; }}
    .document-meta {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 5px; }}
    .doc-chip {{ border: 1px solid var(--line); border-radius: 999px; padding: 2px 7px; color: var(--muted); background: #fff; font-size: 12px; }}
    .doc-chip.risk {{ border-color: #f1c27d; color: #8a4b00; background: #fff8ec; }}
    .doc-chip.source {{ border-color: #9fc1ff; color: #234d8f; background: #eef5ff; font-weight: 800; }}
    .document-open {{ border: 1px solid var(--line); border-radius: 8px; padding: 6px 9px; background: #fff; text-decoration: none; color: var(--text); font-weight: 700; white-space: nowrap; }}
    .pagination {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }}
    .page-button {{ border: 1px solid var(--line); border-radius: 7px; min-width: 34px; height: 32px; padding: 0 9px; background: #fff; color: var(--text); cursor: pointer; font-weight: 700; }}
    .page-button.current {{ background: var(--info); color: #fff; border-color: var(--info); }}
    .page-button:disabled {{ color: var(--muted); cursor: default; background: #f3f5f7; }}
    .dork-list {{ display: grid; gap: 10px; }}
    .dork-status {{ border: 1px solid var(--line); border-radius: 8px; padding: 12px; margin: 12px 0; background: #fbfcfd; }}
    .dork-status b {{ display: block; margin-bottom: 4px; }}
    .dork-status p {{ margin: 0 0 8px; }}
    .dork-status.ok {{ border-left: 6px solid var(--good); }}
    .dork-status.warn {{ border-left: 6px solid var(--medium); background: #fffaf2; }}
    .dork-chips {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
    .dork-chip {{ border: 1px solid #f1c27d; border-radius: 999px; padding: 3px 8px; color: #7a4300; background: #fff; font-size: 12px; font-weight: 700; }}
    .dork-item {{ border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: #fbfcfd; }}
    .links {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
    .links a {{ border: 1px solid var(--line); border-radius: 6px; padding: 4px 7px; text-decoration: none; background: #fff; }}
    .explain {{ background: var(--soft); border-radius: 8px; padding: 12px; margin: 10px 0; }}
    .explain p {{ margin: 0 0 8px; }}
    .explain p:last-child {{ margin-bottom: 0; }}
    .label {{ display: block; font-weight: 700; margin-bottom: 2px; }}
    ul {{ margin: 0; padding-left: 18px; }}
    li {{ overflow-wrap: anywhere; }}
    .empty {{ padding: 16px; color: var(--muted); }}
    .error-list {{ display: grid; gap: 10px; }}
    .error-item {{ border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: #fbfcfd; }}
    .error-item b {{ display: block; margin-bottom: 4px; }}
    .error-item p {{ margin: 0 0 6px; }}
    .error-item p:last-child {{ margin-bottom: 0; }}
    @media (max-width: 760px) {{
      .wrap {{ padding: 18px 12px 36px; }}
      .summary-blocks {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .columns {{ grid-template-columns: 1fr; }}
      .stat b {{ font-size: 21px; }}
      .document-card {{ grid-template-columns: 40px minmax(0, 1fr); }}
      .document-open {{ grid-column: 2; justify-self: start; }}
      h1 {{ font-size: 32px; }}
    }}
  </style>
</head>
<body>
  <main class="wrap">
    <header>
      <p class="muted">Внешний аудит поверхности атаки</p>
      <h1>{escape(context.target.domain)}</h1>
      <p class="muted">Профиль: <code>{escape(context.config.profile)}</code> · Активные проверки: <code>{yes_no(context.config.active)}</code> · Внешние инструменты: <code>{yes_no(context.config.with_tools)}</code> · Heavy: <code>{yes_no(context.config.heavy_tools)}</code> · Dorks auto: <code>{yes_no(context.config.auto_dork_search)}</code></p>
      <section class="client-summary" aria-label="Краткая сводка для клиента">
        <div class="verdict {escape(str(overview['level']))}">
          <p class="eyebrow">Краткая сводка</p>
          <h2 class="verdict-title">{escape(str(overview['title']))}</h2>
          <p class="verdict-message">{escape(str(overview['message']))}</p>
          <h3>Что важно прямо сейчас</h3>
          <ul>{priority_items_html}</ul>
          <p class="read-more">Больше читай в отчете.</p>
        </div>
      </section>
      <section class="summary-blocks" aria-label="Что проверено">
        <div class="summary-block"><b>{len(findings)}</b><span>Всего находок</span></div>
        <div class="summary-block"><b>{len(context.subdomains)}</b><span>Поддомены</span></div>
        <div class="summary-block"><b>{len(context.live_hosts)}</b><span>Живые сервисы</span></div>
        <div class="summary-block"><b>{len(context.endpoints)}</b><span>Endpoints</span></div>
      </section>
      <section class="grid" aria-label="Сводка">
        <div class="stat"><b>{summary.get("critical", 0)}</b><span>Критично</span></div>
        <div class="stat"><b>{summary.get("high", 0)}</b><span>Высоко</span></div>
        <div class="stat"><b>{summary.get("medium", 0)}</b><span>Средне</span></div>
        <div class="stat"><b>{summary.get("low", 0)}</b><span>Низко</span></div>
        <div class="stat"><b>{summary.get("info", 0)}</b><span>Инфо</span></div>
      </section>
    </header>

    <section class="intro">
      <p><b>Как читать отчет.</b> Это автоматическая проверка того, что видно из интернета: домены, поддомены, сайты, порты, заголовки, DNS и типовые признаки уязвимостей.</p>
      <p><b>Критично/Высоко</b> - самые важные сигналы. <b>Средне</b> - заметные настройки, пути или сервисы. <b>Низко/Инфо</b> - дополнительный контекст по внешней поверхности.</p>
      <p>Автосканер может ошибаться, поэтому важные находки требуют ручного подтверждения.</p>
    </section>

    {documents_html}

    <h2>Находки</h2>
    <section class="cards">{cards}</section>

    <h2>Активы</h2>
    <section class="columns">
      {subdomain_panel}
      {live_panel}
      {ips_panel}
      {ports_panel}
      {endpoints_panel}
    </section>

    {dork_html}

    <h2>Артефакты модулей</h2>
    <section class="panel">{artifact_html}</section>

    <h2>Технические ошибки сбора</h2>
    <section class="panel"><p class="muted">{escape(errors_note)}</p>{errors_html}</section>
  </main>
</body>
</html>
"""


def get_public_documents_summary(results: list[ModuleResult], output_path: Path | None = None) -> dict:
    documents: dict[str, dict] = {}
    source_groups: dict[str, dict[str, dict]] = {"site": {}, "dorks": {}}
    for result in results:
        public_documents = result.artifacts.get("public_documents") if result.artifacts else None
        if not isinstance(public_documents, dict):
            continue
        group = "dorks" if result.module == "dork_builder" else "site"
        for item in public_documents.get("documents") or []:
            if isinstance(item, dict) and item.get("url"):
                document = dict(item)
                document["source_group"] = group
                documents.setdefault(str(item["url"]), document)
                source_groups[group].setdefault(str(item["url"]), document)

    if not documents:
        return {}

    ordered = [documents[url] for url in sorted(documents)]
    by_type: dict[str, int] = {}
    by_host: dict[str, int] = {}
    for item in ordered:
        extension = str(item.get("extension") or "").lower()
        host = str(item.get("host") or "")
        if extension:
            by_type[extension] = by_type.get(extension, 0) + 1
        if host:
            by_host[host] = by_host.get(host, 0) + 1
    keyword_matches = [item for item in ordered if item.get("keyword_match") == "yes"]
    summary = {
        "total": len(ordered),
        "by_type": dict(sorted(by_type.items(), key=lambda item: (-item[1], item[0]))),
        "by_host": dict(sorted(by_host.items(), key=lambda item: (-item[1], item[0]))[:20]),
        "keyword_matches": len(keyword_matches),
        "sample": keyword_matches[:30] or ordered[:30],
        "documents": ordered,
        "source_groups": {
            "site": [source_groups["site"][url] for url in sorted(source_groups["site"])],
            "dorks": [source_groups["dorks"][url] for url in sorted(source_groups["dorks"])],
        },
        "checked_total": sum(int((result.artifacts.get("public_documents") or {}).get("checked_total") or 0) for result in results if result.artifacts),
        "rejected_total": sum(int((result.artifacts.get("public_documents") or {}).get("rejected_total") or 0) for result in results if result.artifacts),
    }
    if output_path:
        output_path.write_text(
            "\n".join(json.dumps(item, ensure_ascii=False) for item in ordered) + "\n",
            encoding="utf-8",
        )
        summary["full_list"] = {
            "path": str(output_path),
            "bytes": output_path.stat().st_size,
        }
    return summary


def render_documents_html(context: ScanContext, results: list[ModuleResult]) -> str:
    summary = get_public_documents_summary(results, context.config.out_dir / "public-documents-merged.jsonl")
    if not summary or not summary.get("total"):
        return """
        <h2>Публичные документы</h2>
        <section class="panel"><p class="muted">Автоматический сбор не выделил публичные PDF/Office-документы отдельным списком.</p></section>
        """

    by_type = summary.get("by_type") if isinstance(summary.get("by_type"), dict) else {}
    by_host = summary.get("by_host") if isinstance(summary.get("by_host"), dict) else {}
    documents = summary.get("documents") if isinstance(summary.get("documents"), list) else []
    source_groups = summary.get("source_groups") if isinstance(summary.get("source_groups"), dict) else {}
    site_documents = source_groups.get("site") if isinstance(source_groups.get("site"), list) else []
    dork_documents = source_groups.get("dorks") if isinstance(source_groups.get("dorks"), list) else []
    full_list = summary.get("full_list") if isinstance(summary.get("full_list"), dict) else {}

    type_items = "".join(
        f'<div class="summary-block"><b>{escape(str(count))}</b><span>{escape(str(extension).upper())}</span></div>'
        for extension, count in by_type.items()
    )
    host_rows = "".join(
        f"<tr><td>{escape(str(host))}</td><td>{escape(str(count))}</td></tr>"
        for host, count in list(by_host.items())[:10]
    )
    full_list_note = ""
    if full_list.get("path"):
        full_list_note = (
            f'<p class="muted">Полный список сохранен: <code>{escape(str(full_list["path"]))}</code> '
            f'({escape(str(full_list.get("bytes", 0)))} байт).</p>'
        )

    hosts_table = (
        '<table class="table"><thead><tr><th>Хост</th><th>Документов</th></tr></thead>'
        f"<tbody>{host_rows}</tbody></table>"
        if host_rows
        else '<p class="muted">Нет данных по хостам.</p>'
    )
    site_browser = render_document_browser("site-documents", site_documents, "Документы со страниц сайта")
    dork_browser = render_document_browser("dork-documents", dork_documents, "Документы из дорков", source_label="DORK")
    all_browser = render_document_browser("all-documents", documents, "Все документы")

    return f"""
    <h2>Публичные документы</h2>
    <section class="panel wide">
      <p class="muted">Найдены публичные PDF/Office-файлы по ссылкам внутри страниц сайта и поисковой выдаче. Это не ошибка само по себе, но такие файлы часто нужно отдельно проверять на метаданные и лишнюю публикацию.</p>
      <section class="summary-blocks" aria-label="Документы по типам">
        <div class="summary-block"><b>{escape(str(summary.get("total", 0)))}</b><span>Всего документов</span></div>
        <div class="summary-block"><b>{escape(str(len(site_documents)))}</b><span>Со страниц сайта</span></div>
        <div class="summary-block"><b>{escape(str(len(dork_documents)))}</b><span>Через dorks</span></div>
        <div class="summary-block"><b>{escape(str(summary.get("keyword_matches", 0)))}</b><span>Слова риска в URL</span></div>
        {type_items}
      </section>
      {full_list_note}
      <details class="collapsible" open>
        <summary>Документы со страниц сайта ({escape(str(len(site_documents)))})</summary>
        <div class="collapsible-body">{site_browser}</div>
      </details>
      <details class="collapsible" open>
        <summary>Документы из dorks ({escape(str(len(dork_documents)))})</summary>
        <div class="collapsible-body">{dork_browser}</div>
      </details>
      <details class="collapsible">
        <summary>Все документы вместе ({escape(str(summary.get("total", 0)))})</summary>
        <div class="collapsible-body">{all_browser}</div>
      </details>
      <details class="collapsible">
        <summary>Распределение по хостам</summary>
        <div class="collapsible-body">{hosts_table}</div>
      </details>
      {render_documents_pagination_script()}
    </section>
    """


def render_document_browser(browser_id: str, documents: list, title: str, source_label: str = "") -> str:
    document_cards = "\n".join(
        render_document_card(item, index, source_label=source_label)
        for index, item in enumerate(documents, start=1)
        if isinstance(item, dict)
    )
    if not document_cards:
        return f'<p class="muted">{escape(title)} не найдены.</p>'
    return f"""
      <div class="document-browser" data-document-browser="{escape(browser_id)}">
        <div class="document-toolbar">
          <p class="muted document-page-status">Документы загружаются...</p>
          <nav class="pagination document-pagination-top" aria-label="{escape(title)}"></nav>
        </div>
        <div class="document-list">{document_cards}</div>
        <div class="document-toolbar">
          <p class="muted">По 50 документов на странице</p>
          <nav class="pagination document-pagination-bottom" aria-label="{escape(title)}"></nav>
        </div>
      </div>
    """


def render_document_card(item: dict, index: int, source_label: str = "") -> str:
    url = str(item.get("url") or "")
    href = link_href(url)
    extension = str(item.get("extension") or document_extension_from_url(url) or "file").lower()
    host = str(item.get("host") or safe_host(url) or "")
    keyword = item.get("keyword_match") == "yes"
    title = document_title(url)
    icon_class = escape(extension if extension else "file")
    chips = [
        f'<span class="doc-chip">{escape(extension.upper())}</span>',
    ]
    if host:
        chips.append(f'<span class="doc-chip">{escape(host)}</span>')
    source = source_label or ("DORK" if item.get("source_group") == "dorks" else "")
    if source:
        chips.append(f'<span class="doc-chip source">{escape(source)}</span>')
    if keyword:
        chips.append('<span class="doc-chip risk">слова риска</span>')
    return (
        f'<article class="document-card" data-document-index="{index}">'
        f'<span class="doc-icon {icon_class}" aria-hidden="true">{escape(extension[:4].upper())}</span>'
        '<div class="document-main">'
        f'<a class="document-title" href="{escape(href)}" rel="noreferrer">{escape(title)}</a>'
        f'<div class="document-meta">{"".join(chips)}</div>'
        '</div>'
        f'<a class="document-open" href="{escape(href)}" rel="noreferrer">Открыть</a>'
        '</article>'
    )


def document_title(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    filename = unquote((parsed.path.rsplit("/", 1)[-1] or "").strip())
    return filename or url


def document_extension_from_url(url: str) -> str:
    filename = document_title(url).lower().split("?", 1)[0]
    if "." not in filename:
        return ""
    extension = filename.rsplit(".", 1)[-1]
    return extension[:8] if extension else ""


def safe_host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def link_href(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    if parsed.scheme not in {"http", "https"}:
        return url
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc.encode("idna").decode("ascii") if parsed.netloc else parsed.netloc,
            quote(unquote(parsed.path), safe="/:@!$&'()*+,;=-._~%"),
            parsed.params,
            quote(unquote(parsed.query), safe="=&?/:@!$'()*+,;%-._~"),
            quote(unquote(parsed.fragment), safe="=&?/:@!$'()*+,;%-._~"),
        )
    )


def render_documents_pagination_script() -> str:
    return """
      <script>
        (() => {
          const pageSize = 50;
          document.querySelectorAll("[data-document-browser]").forEach((browser) => {
            const cards = Array.from(browser.querySelectorAll(".document-card"));
            const top = browser.querySelector(".document-pagination-top");
            const bottom = browser.querySelector(".document-pagination-bottom");
            const status = browser.querySelector(".document-page-status");
            if (!cards.length || !top || !bottom || !status) return;
            const pageCount = Math.ceil(cards.length / pageSize);
            let current = 1;

            const pageWindow = () => {
              const pages = new Set([1, pageCount]);
              for (let page = current - 2; page <= current + 2; page += 1) {
                if (page >= 1 && page <= pageCount) pages.add(page);
              }
              return Array.from(pages).sort((a, b) => a - b);
            };

            const button = (label, page, disabled = false, currentPage = false) => {
              const el = document.createElement("button");
              el.type = "button";
              el.className = "page-button" + (currentPage ? " current" : "");
              el.textContent = label;
              el.disabled = disabled;
              el.addEventListener("click", () => render(page));
              return el;
            };

            const renderNav = (container) => {
              container.textContent = "";
              container.appendChild(button("‹", Math.max(1, current - 1), current === 1));
              let previous = 0;
              for (const page of pageWindow()) {
                if (previous && page - previous > 1) {
                  const gap = document.createElement("span");
                  gap.className = "muted";
                  gap.textContent = "...";
                  container.appendChild(gap);
                }
                container.appendChild(button(String(page), page, false, page === current));
                previous = page;
              }
              container.appendChild(button("›", Math.min(pageCount, current + 1), current === pageCount));
            };

            function render(page) {
              current = Math.min(pageCount, Math.max(1, page));
              const start = (current - 1) * pageSize;
              const end = start + pageSize;
              cards.forEach((card, index) => {
                card.hidden = index < start || index >= end;
              });
              status.textContent = `Показаны ${start + 1}-${Math.min(end, cards.length)} из ${cards.length}`;
              renderNav(top);
              renderNav(bottom);
            }

            render(1);
          });
        })();
      </script>
    """


def render_dork_html(results: list[ModuleResult]) -> str:
    dork_result = next((result for result in results if result.module == "dork_builder"), None)
    if not dork_result:
        return ""
    dorks = dork_result.artifacts.get("dorks") or []
    search_results = dork_result.artifacts.get("search_results") or []
    auto_summary = dork_result.artifacts.get("auto_dork_summary") or []
    dork_status_html = render_dork_status_html(dork_result)
    checked_titles = {str(item.get("title")) for item in auto_summary} if auto_summary else set()
    found_titles = {str(item.get("title")) for item in auto_summary if int(item.get("result_count") or 0) > 0}
    if auto_summary:
        dorks_to_show = [item for item in dorks if str(item.get("title")) in found_titles]
    else:
        dorks_to_show = dorks

    dork_items = []
    for item in dorks_to_show:
        dork_items.append(
            f"""
            <article class="dork-item">
              <h3>{escape(str(item.get("title", "Dork")))}</h3>
              <pre><code>{escape(str(item.get("query", "")))}</code></pre>
              <div class="links">
                <a href="{escape(str(item.get("google", "#")))}">Google</a>
                <a href="{escape(str(item.get("bing", "#")))}">Bing</a>
                <a href="{escape(str(item.get("duckduckgo", "#")))}">DuckDuckGo</a>
              </div>
            </article>
            """
        )
    if auto_summary and not dork_items:
        dorks_html = '<section class="empty">Автопроверка не нашла dorks с результатами, поэтому пустые ссылки скрыты.</section>'
    else:
        dorks_html = "\n".join(dork_items) or '<section class="empty">Dorks не сформированы.</section>'

    if auto_summary:
        checked_count = len(checked_titles)
        found_count = len(found_titles)
        empty_count = max(0, checked_count - found_count)
        error_count = sum(1 for item in auto_summary if item.get("errors"))
        dork_note = (
            f"Автопроверка: проверено {checked_count}; с результатами {found_count}; "
            f"пустые скрыты {empty_count}; с ошибками {error_count}."
        )
    else:
        dork_note = "Полный список команд для ручной проверки в Google/Bing/DuckDuckGo."

    rows = []
    for item in search_results:
        url = str(item.get("url", ""))
        href = link_href(url)
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('engine', '')))}</td>"
            f"<td>{escape(str(item.get('dork_title', '')))}</td>"
            f"<td>{escape(str(item.get('title', '')))}</td>"
            f'<td><a href="{escape(href)}">{escape(url)}</a></td>'
            "</tr>"
        )
    search_html = (
        "<table class=\"table\"><thead><tr><th>Источник</th><th>Dork</th><th>Заголовок</th><th>URL</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows
        else '<section class="empty">Автоматическая выдача не вернула результатов или была недоступна.</section>'
    )

    return f"""
    <h2>Google Dorking</h2>
    <section class="panel">
      <p class="muted">{escape(dork_note)}</p>
      {dork_status_html}
      <div class="dork-list">{dorks_html}</div>
    </section>

    <h2>Автоматическая выдача поисковиков</h2>
    <section class="panel">{search_html}</section>
    """


def render_dork_status_html(result: ModuleResult) -> str:
    errors = collect_dork_errors(result)
    if not errors:
        return (
            '<div class="dork-status ok">'
            '<b>Статус автодоркинга</b>'
            '<p>Автоматический поиск не вернул технических ограничений от поисковиков или индексов.</p>'
            '</div>'
        )

    summary = summarize_dork_errors(errors)
    chips = "".join(
        f'<span class="dork-chip">{escape(source)}: {count}</span>'
        for source, count in summary["sources"].items()
    )
    reasons = ", ".join(summary["reasons"]) or "ограничения внешних источников"
    details = "\n".join(f"- {error}" for error in errors[:30])
    if len(errors) > 30:
        details += f"\n- ... еще {len(errors) - 30} записей"

    return (
        '<div class="dork-status warn">'
        '<b>Статус автодоркинга: частично ограничен внешними источниками</b>'
        '<p>Это не уязвимость и не падение сервиса. Часть автоматических запросов к поисковикам/индексам '
        f'не выполнилась: {escape(reasons)}. Найденные результаты сохранены, но выдача может быть неполной.</p>'
        f'<div class="dork-chips">{chips}</div>'
        '<details class="collapsible">'
        '<summary>Показать технические детали доркинга</summary>'
        f'<div class="collapsible-body"><pre><code>{escape(details)}</code></pre></div>'
        '</details>'
        '</div>'
    )


def collect_dork_errors(result: ModuleResult) -> list[str]:
    seen: set[str] = set()
    errors: list[str] = []
    for source in (
        result.artifacts.get("search_errors") if result.artifacts else None,
        result.artifacts.get("index_search_errors") if result.artifacts else None,
        result.errors,
    ):
        if not isinstance(source, list):
            continue
        for item in source:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                errors.append(text)
    return errors


def summarize_dork_errors(errors: list[str]) -> dict[str, object]:
    sources: dict[str, int] = {}
    reason_set: set[str] = set()
    for error in errors:
        source = error.split(":", 1)[0].strip() or "source"
        sources[source] = sources.get(source, 0) + 1
        lower = error.lower()
        if any(marker in lower for marker in ("антибот", "капч", "captcha", "403", "429")):
            reason_set.add("антибот/капча")
        if "timeout" in lower or "timed out" in lower:
            reason_set.add("timeout")
        if "ssl" in lower or "handshake" in lower:
            reason_set.add("SSL handshake timeout")
    return {
        "sources": dict(sorted(sources.items(), key=lambda item: (-item[1], item[0]))),
        "reasons": sorted(reason_set),
    }


def render_artifacts_html(results: list[ModuleResult]) -> str:
    rows = []
    for result in results:
        if not result.artifacts:
            continue
        artifact_json = json.dumps(compact_artifacts(result.artifacts), ensure_ascii=False, indent=2)
        rows.append(
            f"""
            <details>
              <summary><b>{escape(result.module)}</b></summary>
              <pre><code>{escape(artifact_json)}</code></pre>
            </details>
            """
        )
    return "\n".join(rows) or '<p class="muted">Артефактов нет.</p>'


def render_errors_html(results: list[ModuleResult]) -> str:
    items = []
    for result in results:
        if result.module == "dork_builder":
            continue
        for error in result.errors:
            explanation = explain_technical_error(result.module, error)
            raw_error = clean_error_noise(error)
            details = ""
            if raw_error:
                details = (
                    '<details class="collapsible">'
                    '<summary>Технические детали</summary>'
                    f'<div class="collapsible-body"><p><code>{escape(compact_text(raw_error, 900))}</code></p></div>'
                    '</details>'
                )
            items.append(
                '<article class="error-item">'
                f'<b>{escape(result.module)}: {escape(explanation["title"])}</b>'
                f'<p><span class="label">Что это</span>{escape(explanation["what"])}</p>'
                f'<p><span class="label">Влияние на отчет</span>{escape(explanation["impact"])}</p>'
                f'<p><span class="label">Что делать</span>{escape(explanation["action"])}</p>'
                f'{details}'
                '</article>'
            )
    if not items:
        return '<p class="muted">Нет</p>'
    return f'<div class="error-list">{"".join(items)}</div>'


def has_non_dork_errors(results: list[ModuleResult]) -> bool:
    return any(result.errors for result in results if result.module != "dork_builder")


def explain_technical_error(module: str, error: str) -> dict[str, str]:
    text = error.lower()
    if "katana" in text:
        if "частичные endpoints сохранены" in text:
            return {
                "title": "краулер не успел закончить обход, но часть URL сохранена",
                "what": "Katana обходит сайт и собирает публичные страницы/API. На этой цели он уперся в лимит времени.",
                "impact": "Список endpoints есть, но он может быть неполным: часть сайта могла не попасть в отчет.",
                "action": "Если нужна более полная карта URL, перезапустить проверку с большим timeout или меньшим числом целей.",
            }
        return {
            "title": "краулер не смог собрать endpoints",
            "what": "Katana не завершил обход сайта из-за ошибки или таймаута.",
            "impact": "Раздел endpoints может быть пустым или неполным.",
            "action": "Проверить технические детали и при необходимости перезапустить сбор endpoints.",
        }
    if "nuclei" in text:
        if "частичных jsonl-находок нет" in text:
            return {
                "title": "проверка шаблонов не успела завершиться",
                "what": "Nuclei проверяет известные признаки уязвимостей по шаблонам. На этой цели процесс закончился по timeout.",
                "impact": "В этом запуске Nuclei не дал подтвержденных находок. Это не доказывает, что уязвимостей нет.",
                "action": "Для уверенности перезапустить Nuclei с большим timeout, меньшим списком целей или отдельной ручной проверкой важных сервисов.",
            }
        if "частичные находки сохранены" in text:
            return {
                "title": "проверка шаблонов не успела завершиться, часть находок сохранена",
                "what": "Nuclei начал проверку уязвимостей, но остановился по timeout.",
                "impact": "Сохраненные находки можно смотреть, но список может быть неполным.",
                "action": "Разобрать сохраненные находки и перезапустить проверку для полной картины.",
            }
        return {
            "title": "проверка шаблонов завершилась технической ошибкой",
            "what": "Nuclei не смог штатно завершить проверку.",
            "impact": "Автоматические проверки уязвимостей могли не попасть в отчет.",
            "action": "Посмотреть технические детали и повторить запуск после устранения причины.",
        }
    if "amass" in text:
        return {
            "title": "пассивный поиск поддоменов не дал результата за отведенное время",
            "what": "Amass ищет поддомены во внешних источниках. В этом запуске он не вернул полезный результат и вывел только служебный прогресс.",
            "impact": "Отчет все равно содержит поддомены из других источников, но данные Amass могли не дополнить инвентарь.",
            "action": "Можно не считать это уязвимостью. При необходимости перезапустить Amass отдельно или увеличить timeout.",
        }
    if "timeout" in text:
        return {
            "title": "инструмент остановился по timeout",
            "what": "Модуль работал дольше разрешенного времени и был остановлен.",
            "impact": "Данные этого модуля могут быть неполными.",
            "action": "Перезапустить проверку с большим timeout или сузить цель.",
        }
    if "не найден" in text:
        return {
            "title": "инструмент не установлен",
            "what": "Внешний CLI-инструмент недоступен на машине, где запускался скан.",
            "impact": "Часть проверок не выполнялась.",
            "action": "Установить инструмент или запускать отчет без этого модуля.",
        }
    return {
        "title": "модуль завершился технической ошибкой",
        "what": "Это ошибка процесса сбора данных, а не подтвержденная уязвимость.",
        "impact": "Часть данных могла не попасть в отчет.",
        "action": "Посмотреть технические детали и повторить запуск при необходимости.",
    }


def clean_error_noise(value: str) -> str:
    text = value.strip()
    progress_only = re.sub(r"\d+\s*/\s*\d+\s*\[[^\]]+\]\s*\d+(?:\.\d+)?%\s*\?\s*p/s", "", text)
    progress_only = progress_only.strip()
    if not progress_only or progress_only == "amass завершился ошибкой:":
        return ""
    return text


def render_data_panel(title: str, items_html: str, count: int, wide: bool = False) -> str:
    classes = "panel wide" if wide else "panel"
    if count > 20:
        return (
            f'<div class="{classes}">'
            f'<details class="collapsible">'
            f'<summary>{escape(title)} - показать список</summary>'
            f'<div class="collapsible-body"><ul>{items_html}</ul></div>'
            f'</details>'
            f'</div>'
        )
    return f'<div class="{classes}"><h3>{escape(title)}</h3><ul>{items_html}</ul></div>'


def render_collapsible_json(title: str, value: dict, open_by_default: bool = False) -> str:
    value_json = json.dumps(value, ensure_ascii=False, indent=2)
    open_attr = " open" if open_by_default else ""
    line_count = value_json.count("\n") + 1
    char_count = len(value_json)
    summary = f"{title} - показать JSON ({line_count} строк, {char_count} символов)"
    return (
        f'<details class="collapsible"{open_attr}>'
        f'<summary>{escape(summary)}</summary>'
        f'<div class="collapsible-body"><pre><code>{escape(value_json)}</code></pre></div>'
        f'</details>'
    )


def compact_artifacts(artifacts: dict) -> dict:
    compact = {}
    for key, value in artifacts.items():
        if key in {"dorks", "search_results"}:
            compact[key] = summarize_list(value, limit=8)
        elif key.endswith("_tail"):
            compact[key] = summarize_list(value, limit=5)
        else:
            compact[key] = compact_value(value)
    return compact


def compact_value(value):
    if isinstance(value, dict):
        return {str(key): compact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return summarize_list(value, limit=20)
    if isinstance(value, str):
        return compact_text(value)
    return value


def summarize_list(items, limit: int) -> list:
    if not isinstance(items, list):
        return compact_value(items)
    compacted = [compact_value(item) for item in items[:limit]]
    if len(items) > limit:
        compacted.append(f"... еще {len(items) - limit} записей; полный список есть в report.json или отдельном артефакте")
    return compacted


def compact_text(value: str, limit: int = 500) -> str:
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + f"... [обрезано, всего {len(value)} символов]"


def render_finding_card(finding: Finding) -> str:
    guide = finding_guide(finding)
    evidence = ""
    if finding.evidence:
        evidence = render_collapsible_json("Доказательства", finding.evidence)
    refs = ""
    if finding.references:
        links = "".join(f'<li><a href="{escape(ref)}">{escape(ref)}</a></li>' for ref in finding.references)
        refs = f"<p><b>Ссылки:</b></p><ul>{links}</ul>"
    severity = finding.severity.value
    return f"""
      <article class="card {escape(severity)}">
        <div class="meta">
          <span class="pill sev {escape(severity)}">{escape(severity_label(severity))}</span>
          <span class="pill">Модуль: {escape(finding.module)}</span>
          <span class="pill">Уверенность: {escape(confidence_label(finding.confidence.value))}</span>
        </div>
        <h3>{escape(finding.title)}</h3>
        <p><b>Цель:</b> <code>{escape(finding.target)}</code></p>
        <div class="explain">
          <p><span class="label">Что это</span>{escape(finding.explanation or guide["explanation"])}</p>
          <p><span class="label">Чем грозит</span>{escape(finding.impact or guide["impact"])}</p>
          <p><span class="label">Что сделать</span>{escape(finding.fix or finding.recommendation or guide["fix"])}</p>
        </div>
        {evidence}
        {refs}
      </article>
    """


def finding_guide(finding: Finding) -> dict[str, str]:
    text = f"{finding.title} {finding.module}".lower()
    if "spf" in text:
        return {
            "explanation": "SPF - DNS-запись, которая говорит почтовым сервисам, какие серверы имеют право отправлять почту от имени домена.",
            "impact": "Без SPF злоумышленникам проще подделывать письма от имени компании, а легитимная почта чаще попадает в спам.",
            "fix": "Добавить SPF-запись в DNS и перечислить только реальные сервисы отправки почты.",
        }
    if "dmarc" in text:
        return {
            "explanation": "DMARC - политика, которая говорит почтовым сервисам, что делать с письмами, не прошедшими SPF/DKIM.",
            "impact": "Без DMARC сложнее защититься от фишинга от имени домена и контролировать подделку корпоративной почты.",
            "fix": "Добавить DMARC-запись, сначала в режиме мониторинга, затем перейти к quarantine или reject.",
        }
    if "caa" in text:
        return {
            "explanation": "CAA - DNS-запись, которая ограничивает, какие центры сертификации могут выпускать TLS-сертификаты для домена.",
            "impact": "Без CAA контроль над выпуском сертификатов слабее, а расследовать ошибочные выпуски сложнее.",
            "fix": "Добавить CAA-записи для тех центров сертификации, которыми компания реально пользуется.",
        }
    if "certificate transparency" in text or "ct_subdomains" in text:
        return {
            "explanation": "Certificate Transparency - публичные журналы выпущенных TLS-сертификатов. По ним видны старые и текущие поддомены.",
            "impact": "Старые поддомены могут указывать на забытые сервисы, тестовые окружения или активы без владельца.",
            "fix": "Сверить список с реальным инвентарем, удалить лишние DNS-записи и закрыть неиспользуемые сервисы.",
        }
    if "dork" in text:
        return {
            "explanation": "Dorks - специальные поисковые запросы, которые помогают найти проиндексированные файлы, админки, логи и бэкапы.",
            "impact": "Если поисковик видит лишние файлы, их может найти любой человек без доступа к вашей инфраструктуре.",
            "fix": "Открыть ссылки из отчета, проверить выдачу и убрать из индекса все чувствительные материалы.",
        }
    if "header" in text or "заголов" in text:
        return {
            "explanation": "Security headers - настройки HTTP-ответа, которые включают защиту браузера от части типовых атак.",
            "impact": "Без них выше риск XSS, clickjacking, утечек referrer-данных и небезопасного поведения браузера.",
            "fix": "Добавить недостающие заголовки на уровне приложения, reverse proxy или CDN.",
        }
    if "tls" in text or "сертификат" in text:
        return {
            "explanation": "TLS отвечает за HTTPS-шифрование и доверие браузера к сайту.",
            "impact": "Проблемы с TLS могут ломать доступ пользователей, снижать доверие и открывать путь к атакам на соединение.",
            "fix": "Обновить сертификаты, отключить старые протоколы и проверить автоматическое продление.",
        }
    if "порт" in text or "port" in text or "naabu" in text:
        return {
            "explanation": "Открытый порт означает, что сервис доступен из интернета.",
            "impact": "Лишние открытые сервисы увеличивают поверхность атаки, особенно если это базы данных или админские интерфейсы.",
            "fix": "Оставить публичными только нужные сервисы, остальное закрыть firewall, VPN или allowlist.",
        }
    if "nuclei" in text:
        return {
            "explanation": "Nuclei проверяет известные признаки уязвимостей и неправильных настроек по шаблонам.",
            "impact": "Такая находка часто указывает на конкретную misconfig/CVE, но ее нужно подтвердить вручную.",
            "fix": "Проверить найденный URL/шаблон, затем исправить настройку или обновить уязвимый компонент.",
        }
    if "endpoint" in text or "katana" in text:
        return {
            "explanation": "Endpoint - публичный URL или API-ручка, найденная краулером.",
            "impact": "Старые или тестовые endpoints могут раскрывать лишние данные или оставаться без контроля доступа.",
            "fix": "Проверить найденные endpoints, удалить устаревшие и закрыть служебные ручки авторизацией.",
        }
    return {
        "explanation": "Это сигнал автоматического сканера, который стоит проверить вручную.",
        "impact": "Риск зависит от конкретного сервиса и контекста, но такие сигналы помогают найти слабые места раньше злоумышленников.",
        "fix": "Проверить доказательства, назначить владельца и исправить проблему по рекомендации ниже.",
    }


def severity_label(value: str) -> str:
    return {
        "critical": "Критично",
        "high": "Высоко",
        "medium": "Средне",
        "low": "Низко",
        "info": "Инфо",
    }.get(value, value)


def confidence_label(value: str) -> str:
    return {
        "high": "высокая",
        "medium": "средняя",
        "low": "низкая",
    }.get(value, value)


def yes_no(value: bool) -> str:
    return "да" if value else "нет"


def render_ports(open_ports: dict[str, set[int]]) -> str:
    if not open_ports:
        return "<li>Нет данных</li>"
    items = []
    for host, ports in sorted(open_ports.items())[:120]:
        port_text = ", ".join(str(port) for port in sorted(ports))
        items.append(f"<li><code>{escape(host)}</code>: {escape(port_text)}</li>")
    return "\n".join(items)
