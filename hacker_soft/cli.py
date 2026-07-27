from __future__ import annotations

import argparse
from pathlib import Path

from .core.models import ScanConfig
from .core.report import flatten_findings
from .scanner import scan
from .tooling import render_tool_inventory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hacker-soft")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("tools", help="Show optional backend tool status")

    scan_parser = subparsers.add_parser("scan", help="Scan an owned external domain")
    scan_parser.add_argument("target", help="Domain or URL, for example example.com")
    scan_parser.add_argument("--company", help="Company name for report context")
    scan_parser.add_argument("--profile", choices=["fast", "standard", "deep"], default="standard")
    scan_parser.add_argument("--active", action="store_true", help="Enable safe active checks")
    scan_parser.add_argument("--with-tools", action="store_true", help="Use optional installed CLI tools")
    scan_parser.add_argument("--heavy-tools", action="store_true", help="Use heavy workflow tools such as reconFTW")
    scan_parser.add_argument("--auto-dork-search", action="store_true", help="Fetch and parse search-engine results for generated dorks")
    scan_parser.add_argument("--max-dork-queries", type=int, default=50, help="Maximum dork queries to fetch automatically")
    scan_parser.add_argument("--max-dork-results", type=int, default=50, help="Maximum parsed results per dork query")
    scan_parser.add_argument("--timeout", type=int, default=10, help="Network timeout in seconds")
    scan_parser.add_argument("--max-hosts", type=int, default=200, help="Maximum hosts to process")
    scan_parser.add_argument("--out", type=Path, default=Path("reports/latest"), help="Report output directory")

    pentest_parser = subparsers.add_parser("pentest", help="Run automated owned-asset pentest: recon, vuln checks, dork collection")
    pentest_parser.add_argument("target", help="Owned domain or URL, for example example.com")
    pentest_parser.add_argument("--company", help="Company name for report context")
    pentest_parser.add_argument("--heavy-tools", action="store_true", help="Also run heavy workflow tools such as reconFTW")
    pentest_parser.add_argument("--timeout", type=int, default=12, help="Network timeout in seconds")
    pentest_parser.add_argument("--max-hosts", type=int, default=250, help="Maximum hosts to process")
    pentest_parser.add_argument("--max-dork-queries", type=int, default=50, help="Maximum dork queries to fetch automatically")
    pentest_parser.add_argument("--max-dork-results", type=int, default=50, help="Maximum parsed results per dork query")
    pentest_parser.add_argument("--out", type=Path, default=Path("reports/pentest-latest"), help="Report output directory")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "tools":
        print(render_tool_inventory())
    elif args.command == "scan":
        config = ScanConfig(
            profile=args.profile,
            active=args.active,
            with_tools=args.with_tools,
            heavy_tools=args.heavy_tools,
            auto_dork_search=args.auto_dork_search,
            max_dork_queries=args.max_dork_queries,
            max_dork_results=args.max_dork_results,
            timeout_seconds=args.timeout,
            max_hosts=args.max_hosts,
            out_dir=args.out,
        )
        print_scan_result(args.target, config, company=args.company)
    elif args.command == "pentest":
        config = ScanConfig(
            profile="deep",
            active=True,
            with_tools=True,
            heavy_tools=args.heavy_tools,
            auto_dork_search=True,
            max_dork_queries=args.max_dork_queries,
            max_dork_results=args.max_dork_results,
            timeout_seconds=args.timeout,
            max_hosts=args.max_hosts,
            out_dir=args.out,
        )
        print_scan_result(args.target, config, company=args.company)


def print_scan_result(target: str, config: ScanConfig, company: str | None = None) -> None:
    context, results, paths = scan(target, config, company=company)
    findings = flatten_findings(results)
    print(f"Цель: {context.target.domain}")
    print(f"Поддомены: {len(context.subdomains)}")
    print(f"Живые HTTP(S): {len(context.live_hosts)}")
    print(f"Endpoints: {len(context.endpoints)}")
    print(f"Находки: {len(findings)}")
    print(f"JSON: {paths['json']}")
    print(f"Markdown: {paths['markdown']}")
    print(f"HTML: {paths['html']}")


if __name__ == "__main__":
    main()
