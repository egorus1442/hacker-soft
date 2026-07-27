from collections import Counter
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
from urllib.parse import quote

from hacker_soft.core.findings import collect_findings, diagnostics, inventory, issues, severity_counter
from hacker_soft.core.models import (
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ScanConfig,
    ScanContext,
    Severity,
    Target,
)
from hacker_soft.core.net import normalize_domain
from hacker_soft.core.net import HttpResponse
from hacker_soft.core.report import flatten_findings, link_href, render_dork_html, render_html, render_markdown
from hacker_soft.bot import parse_domain_request, parse_scan_request
from hacker_soft.scanner import default_modules
from hacker_soft.modules.ct_subdomains import add_owned_name
from hacker_soft.modules.dorks import DorkBuilderModule, normalize_result_url
from hacker_soft.modules.exposure_paths import ExposurePathsModule
from hacker_soft.modules.projectdiscovery import (
    ProjectDiscoveryModule,
    extract_documents_from_katana,
    stream_katana_endpoints,
)
from hacker_soft.modules.urlscan import UrlscanModule


READY_TEMPLATES = {"ready": True, "path": "/opt/nuclei-templates", "count": 500, "searched": []}


def patch_nuclei_templates():
    return patch(
        "hacker_soft.modules.projectdiscovery.find_nuclei_templates",
        return_value=dict(READY_TEMPLATES),
    )


class CoreTests(TestCase):
    def test_normalize_domain_from_url(self):
        self.assertEqual(normalize_domain("https://www.Example.COM/path"), "example.com")

    def test_dork_builder_generates_search_links(self):
        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test")),
        )

        result = DorkBuilderModule().run(context)

        self.assertTrue(result.findings)
        self.assertTrue(result.artifacts["dorks"])
        self.assertIn("site:example.com", result.artifacts["dorks"][0]["query"])

    def test_dork_builder_includes_extended_document_queries(self):
        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test")),
        )

        result = DorkBuilderModule().run(context)
        queries = "\n".join(item["query"] for item in result.artifacts["dorks"])

        self.assertIn("filetype:pptx", queries)
        self.assertIn("filetype:csv", queries)
        self.assertIn("конфиденциально", queries)

    def test_dork_builder_can_parse_search_results(self):
        html = """
        <html><body>
          <a href="https://www.bing.com/search?q=example.com">Bing</a>
          <a href="https://docs.example.com/public/report.pdf">Quarterly report</a>
          <a href="/l/?uddg=https%3A%2F%2Fgithub.com%2Facme%2Fdemo%2Fblob%2Fmain%2FREADME.md">example.com readme</a>
        </body></html>
        """

        def fake_http_get(url, **_kwargs):
            return HttpResponse(url=url, status=200, headers={}, body_sample=html)

        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(
                out_dir=Path("/tmp/test"),
                auto_dork_search=True,
                max_dork_queries=1,
                max_dork_results=5,
            ),
        )

        with patch("hacker_soft.modules.dorks.http_get", fake_http_get):
            result = DorkBuilderModule().run(context)

        self.assertEqual(result.artifacts["search_result_count"], 2)
        self.assertIn("https://docs.example.com/public/report.pdf", context.endpoints)
        self.assertTrue(any(item["engine"] == "duckduckgo_lite" for item in result.artifacts["search_results"]))

    def test_dork_parser_decodes_bing_redirect_urls(self):
        encoded = "a1aHR0cHM6Ly9kb2NzLmV4YW1wbGUuY29tL3B1YmxpYy9yZXBvcnQucGRm"

        url = normalize_result_url(f"https://www.bing.com/ck/a?u={encoded}")

        self.assertEqual(url, "https://docs.example.com/public/report.pdf")

    def test_katana_document_extractor_reads_links_from_response_body(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "katana-output.jsonl"
            output.write_text(
                json.dumps(
                    {
                        "request": {"endpoint": "https://www.example.com/about/"},
                        "response": {
                            "body": (
                                '<a href="/media/File/ContractInfo_Apr14.pdf">PDF</a>'
                                '<a href="https://www.example.com/forms/zayavka.doc">DOC</a>'
                                '<a href="https://other.test/private.pdf">Other</a>'
                            )
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            summary = extract_documents_from_katana(output, "example.com")

        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_type"], {"doc": 1, "pdf": 1})
        urls = {item["url"] for item in summary["documents"]}
        self.assertIn("https://example.com/media/File/ContractInfo_Apr14.pdf", urls)
        self.assertIn("https://example.com/forms/zayavka.doc", urls)

    def test_report_hides_dorks_without_auto_results(self):
        result = ModuleResult(
            module="dork_builder",
            artifacts={
                "dorks": [
                    {
                        "title": "Found dork",
                        "query": "site:example.com filetype:pdf",
                        "google": "https://google.test/found",
                        "bing": "https://bing.test/found",
                        "duckduckgo": "https://duck.test/found",
                    },
                    {
                        "title": "Empty dork",
                        "query": "site:example.com filetype:sql",
                        "google": "https://google.test/empty",
                        "bing": "https://bing.test/empty",
                        "duckduckgo": "https://duck.test/empty",
                    },
                ],
                "auto_dork_summary": [
                    {"title": "Found dork", "result_count": 1, "errors": []},
                    {"title": "Empty dork", "result_count": 0, "errors": []},
                ],
                "search_results": [
                    {
                        "engine": "bing",
                        "dork_title": "Found dork",
                        "title": "Public PDF",
                        "url": "https://docs.example.com/report.pdf",
                    }
                ],
            },
        )

        html = render_dork_html([result])

        self.assertIn("Found dork", html)
        self.assertIn("пустые скрыты 1", html)
        self.assertNotIn("Empty dork", html)

    def test_report_separates_dork_source_limits_from_module_errors(self):
        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test"), auto_dork_search=True),
        )
        dork_result = ModuleResult(
            module="dork_builder",
            artifacts={
                "dorks": [],
                "auto_dork_summary": [],
                "search_errors": [
                    "bing: dork 'PDF-документы' не выполнен: bing: поисковик показал антибот/капчу",
                    "google: dork 'Дампы' не выполнен: The read operation timed out",
                ],
            },
            errors=[
                "bing: dork 'PDF-документы' не выполнен: bing: поисковик показал антибот/капчу",
            ],
        )

        html = render_html(context, [dork_result], [], Counter())

        self.assertIn("Статус автодоркинга: частично ограничен внешними источниками", html)
        self.assertIn("bing: 1", html)
        self.assertIn("google: 1", html)
        self.assertIn("Все модули завершились без технических ошибок.", html)
        self.assertNotIn("dork_builder: модуль завершился технической ошибкой", html)

    def test_report_starts_with_client_oriented_summary(self):
        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test"), active=True, with_tools=True),
            subdomains={"www.example.com", "api.example.com"},
            live_hosts={"https://www.example.com"},
            endpoints={"https://www.example.com/login"},
            open_ports={"example.com": {3389}},
        )
        result = ModuleResult(
            module="projectdiscovery",
            findings=[
                Finding(
                    module="projectdiscovery",
                    title="Потенциально опасные сетевые сервисы доступны из интернета",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    target="example.com",
                    evidence={"hosts": {"example.com": [3389, 5432]}},
                )
            ],
        )
        findings = flatten_findings([result])
        summary = Counter({"critical": 1})

        markdown = render_markdown(context, [result], findings, summary)
        html = render_html(context, [result], findings, summary)

        self.assertLess(markdown.index("## Краткая сводка для клиента"), markdown.index("## Проблемы к исправлению"))
        self.assertNotIn("Что сделать первым", markdown)
        self.assertIn("Больше читай в отчете.", markdown)
        self.assertIn("Что важно прямо сейчас", html)
        self.assertNotIn("Что сделать первым", html)
        self.assertIn("Больше читай в отчете.", html)
        self.assertIn("<details class=\"collapsible\"", html)
        self.assertIn("Доказательства - показать JSON", html)

    def test_report_renders_all_documents_before_findings_with_pagination(self):
        with TemporaryDirectory() as tmp:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmp), active=True),
            )
            documents = [
                {
                    "url": f"https://www.example.com/docs/report-{index}.pdf",
                    "extension": "pdf",
                    "host": "www.example.com",
                    "keyword_match": "yes" if index == 55 else "no",
                }
                for index in range(1, 56)
            ]
            result = ModuleResult(
                module="projectdiscovery",
                findings=[
                    Finding(
                        module="projectdiscovery",
                        title="Test finding",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        target="example.com",
                    )
                ],
                artifacts={
                    "public_documents": {
                        "total": len(documents),
                        "by_type": {"pdf": len(documents)},
                        "by_host": {"www.example.com": len(documents)},
                        "keyword_matches": 1,
                        "sample": documents[:30],
                        "documents": documents,
                    }
                },
            )
            dork_result = ModuleResult(
                module="dork_builder",
                artifacts={
                    "public_documents": {
                        "total": 1,
                        "by_type": {"pdf": 1},
                        "by_host": {"docs.example.com": 1},
                        "keyword_matches": 0,
                        "sample": [],
                        "documents": [
                            {
                                "url": "https://docs.example.com/dork-report.pdf",
                                "extension": "pdf",
                                "host": "docs.example.com",
                                "keyword_match": "no",
                            }
                        ],
                    }
                },
            )
            results = [result, dork_result]
            findings = flatten_findings(results)

            markdown = render_markdown(context, results, findings, Counter({"info": 1}))
            html = render_html(context, results, findings, Counter({"info": 1}))

        self.assertLess(html.index("<h2>Публичные документы</h2>"), html.index("<h2>Проблемы к исправлению"))
        self.assertIn("document-pagination-top", html)
        self.assertIn("document-card", html)
        self.assertIn("report-55.pdf", html)
        self.assertIn("Документы из dorks (1)", html)
        self.assertIn("doc-chip source", html)
        self.assertIn("dork-report.pdf", html)
        self.assertIn("pageSize = 50", html)
        self.assertIn("Документы из dorks (1):", markdown)
        self.assertIn("[DORK] https://docs.example.com/dork-report.pdf", markdown)
        self.assertIn("Все документы вместе:", markdown)
        self.assertIn("report-55.pdf", markdown)

    def test_report_encodes_document_hrefs(self):
        url = "https://www.example.com/upload/Протокол открытия доступа.pdf"

        self.assertEqual(
            link_href(url),
            "https://www.example.com/upload/%D0%9F%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB%20%D0%BE%D1%82%D0%BA%D1%80%D1%8B%D1%82%D0%B8%D1%8F%20%D0%B4%D0%BE%D1%81%D1%82%D1%83%D0%BF%D0%B0.pdf",
        )

    def test_report_explains_tool_errors_without_progress_noise(self):
        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test")),
        )
        result = ModuleResult(
            module="projectdiscovery",
            errors=[
                "katana завершился ошибкой: timeout, но частичные endpoints сохранены; output=katana-output.jsonl",
                "nuclei завершился ошибкой: timeout; частичных JSONL-находок нет; stderr_log=nuclei-stderr.log",
            ],
        )
        amass_result = ModuleResult(
            module="amass",
            errors=[
                "amass завершился ошибкой: 0 / 1 [________________________________] 0.00% ? p/s"
            ],
        )

        html = render_html(context, [result, amass_result], [], Counter())

        preview = html.split("<h2>Технические ошибки сбора</h2>", 1)[0]

        self.assertNotIn("Есть технические ошибки сбора", preview)
        self.assertIn("краулер не успел закончить обход", html)
        self.assertIn("проверка шаблонов не успела завершиться", html)
        self.assertIn("служебный прогресс", html)
        self.assertNotIn("________________________________", html)

    def test_urlscan_filters_unrelated_domains(self):
        def fake_fetch_json(_url, timeout=20):
            return {
                "results": [
                    {"page": {"domain": "app.example.com", "url": "https://app.example.com/login"}},
                    {"page": {"domain": "other.test", "url": "https://other.test/"}},
                ]
            }

        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test")),
        )

        with patch("hacker_soft.modules.urlscan.fetch_json", fake_fetch_json):
            result = UrlscanModule().run(context)

        self.assertEqual(result.artifacts["url_count"], 1)
        self.assertEqual(result.artifacts["sample_urls"], ["https://app.example.com/login"])
        self.assertIn("app.example.com", context.subdomains)

    def test_parse_deep_bot_command(self):
        request = parse_scan_request("/deep https://www.example.com/path")

        self.assertIsNotNone(request)
        self.assertEqual(request["domain"], "example.com")
        self.assertEqual(request["profile"], "deep")
        self.assertTrue(request["active"])
        self.assertTrue(request["with_tools"])
        self.assertFalse(request["heavy_tools"])

    def test_bot_commands_always_use_full_default_scan(self):
        request = parse_scan_request("/fast example.com passive no-dorks")

        self.assertIsNotNone(request)
        self.assertEqual(request["domain"], "example.com")
        self.assertEqual(request["profile"], "deep")
        self.assertTrue(request["active"])
        self.assertTrue(request["with_tools"])
        self.assertTrue(request["auto_dork_search"])
        self.assertEqual(request["max_dork_queries"], 50)
        self.assertEqual(request["max_dork_results"], 50)
        self.assertEqual(request["max_hosts"], 250)

    def test_parse_pentest_bot_command_enables_tools_and_dorks(self):
        request = parse_scan_request("/pentest example.com")

        self.assertIsNotNone(request)
        self.assertEqual(request["domain"], "example.com")
        self.assertEqual(request["profile"], "deep")
        self.assertTrue(request["active"])
        self.assertTrue(request["with_tools"])
        self.assertTrue(request["auto_dork_search"])

    def test_parse_domain_request_defaults_to_deep(self):
        request = parse_domain_request("https://www.example.com/path")

        self.assertIsNotNone(request)
        self.assertEqual(request["domain"], "example.com")
        self.assertEqual(request["profile"], "deep")
        self.assertTrue(request["active"])
        self.assertTrue(request["with_tools"])
        self.assertFalse(request["heavy_tools"])
        self.assertTrue(request["auto_dork_search"])
        self.assertEqual(request["max_dork_queries"], 50)
        self.assertEqual(request["max_dork_results"], 50)
        self.assertEqual(request["max_hosts"], 250)

    def test_ct_name_normalization(self):
        names = set()

        add_owned_name(names, "*.Api.Example.com.", "example.com")
        add_owned_name(names, "other.test", "example.com")

        self.assertEqual(names, {"api.example.com"})

    def test_katana_uses_jsonl_flag(self):
        captured_args = []
        captured_kwargs = {}

        def fake_run_tool(args, **_kwargs):
            captured_args.append(args)
            captured_kwargs.update(_kwargs)
            return 0, '{"url":"https://app.example.com/login"}\n', ""

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir)),
                live_hosts={"https://app.example.com"},
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool):
                ProjectDiscoveryModule()._katana(context, result)

        self.assertEqual(result.artifacts["katana_endpoints"], 1)
        self.assertIn("https://app.example.com/login", context.endpoints)
        self.assertIn("-jsonl", captured_args[0])
        self.assertIn("-omit-raw", captured_args[0])
        self.assertNotIn("-json", captured_args[0])
        self.assertEqual(str(captured_kwargs["stdout_path"]), os.devnull)

    def test_nuclei_reads_partial_jsonl_export_after_timeout(self):
        captured_kwargs = {}

        def fake_run_tool(args, **_kwargs):
            captured_kwargs.update(_kwargs)
            output_path = Path(args[args.index("-jsonl-export") + 1])
            output_path.write_text(
                '{"template-id":"demo-template","matched-at":"https://app.example.com",'
                '"info":{"name":"Demo finding","severity":"high"}}\n',
                encoding="utf-8",
            )
            return 124, "", "timeout"

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir)),
                live_hosts={"https://app.example.com"},
            )
            module = ProjectDiscoveryModule()
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool), patch_nuclei_templates():
                module._nuclei(context, result)

        self.assertEqual(result.artifacts["nuclei_findings"], 1)
        self.assertEqual(result.findings[0].title, "Nuclei: Demo finding")
        self.assertIn("частичные находки сохранены", result.errors[0])
        self.assertEqual(captured_kwargs["stdout_path"].name, "nuclei-stdout.log")
        self.assertEqual(captured_kwargs["stderr_path"].name, "nuclei-stderr.log")
        self.assertEqual(result.artifacts["nuclei_stderr_log"]["path"], str(captured_kwargs["stderr_path"]))

    def test_deep_modules_do_not_include_blind_port_scan(self):
        names = [module.name for module in default_modules("deep")]

        self.assertIn("projectdiscovery", names)
        self.assertNotIn("port_scan", names)

    def test_nuclei_deduplicates_same_template_target_and_name(self):
        def fake_run_tool(args, **_kwargs):
            output_path = Path(args[args.index("-jsonl-export") + 1])
            output_path.write_text(
                "\n".join(
                    [
                        '{"template-id":"waf-detect","matched-at":"https://app.example.com/",'
                        '"matcher-name":"nginx","info":{"name":"WAF Detection","severity":"info"}}',
                        '{"template-id":"waf-detect","matched-at":"https://app.example.com",'
                        '"matcher-name":"nginx","info":{"name":"WAF Detection","severity":"info"}}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            return 0, "", ""

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir)),
                live_hosts={"https://app.example.com"},
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool), patch_nuclei_templates():
                ProjectDiscoveryModule()._nuclei(context, result)

        self.assertEqual(result.artifacts["nuclei_findings"], 1)

    def test_nuclei_without_templates_reports_missing_coverage(self):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("nuclei must not run without templates")

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir)),
                live_hosts={"https://app.example.com"},
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fail_if_called), patch(
                "hacker_soft.modules.projectdiscovery.find_nuclei_templates",
                return_value={"ready": False, "path": "", "count": 0, "searched": ["/opt/nuclei-templates"]},
            ):
                ProjectDiscoveryModule()._nuclei(context, result)

        self.assertFalse(result.artifacts["nuclei_templates"]["ready"])
        self.assertIn("шаблон", result.errors[0])
        self.assertEqual(result.findings, [])

    def test_missing_templates_are_explained_as_zero_coverage(self):
        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test")),
        )
        raw_nuclei_error = ModuleResult(
            module="projectdiscovery",
            errors=["nuclei завершился ошибкой: Could not run nuclei: no templates provided for scan"],
        )

        html = render_html(context, [raw_nuclei_error], [], Counter())

        self.assertIn("нет набора шаблонов", html)
        self.assertNotIn("проверка шаблонов не успела завершиться", html)

    def test_naabu_accept_all_host_is_reported_as_noisy_not_risky(self):
        risky_ports = [21, 1433, 2049, 3306, 3389, 5432, 5900]

        def fake_run_tool(_args, **_kwargs):
            stdout = "\n".join(f'{{"host":"example.com","port":{port}}}' for port in risky_ports)
            return 0, stdout, ""

        banner_checks = {
            "example.com": {
                str(port): {"banner_found": False, "status": "no_banner"}
                for port in risky_ports
            }
        }

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir), active=True, with_tools=True),
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool), patch(
                "hacker_soft.modules.projectdiscovery.collect_port_banners",
                return_value=banner_checks,
            ), patch(
                "hacker_soft.modules.projectdiscovery.probe_accept_all_host",
                return_value={"control_ports_tested": [1, 2, 3, 7, 9], "control_ports_open": [1, 2, 3, 7, 9]},
            ), patch(
                "hacker_soft.modules.projectdiscovery.collect_host_infrastructure",
                return_value={},
            ):
                ProjectDiscoveryModule()._naabu(context, result)

        titles = [finding.title for finding in result.findings]
        self.assertIn("Результат port scan выглядит шумным и требует перепроверки", titles)
        self.assertNotIn("Потенциально опасные сетевые сервисы доступны из интернета", titles)
        self.assertEqual(result.artifacts["naabu_noisy_hosts"]["example.com"]["reason"], "control_ports_also_open")
        self.assertEqual(result.artifacts["open_ports_without_banners"]["example.com"], risky_ports)

    def test_naabu_only_flags_risky_ports_with_banners(self):
        ports = [21, 3306, 3389]

        def fake_run_tool(_args, **_kwargs):
            stdout = "\n".join(f'{{"host":"example.com","port":{port}}}' for port in ports)
            return 0, stdout, ""

        banner_checks = {
            "example.com": {
                "21": {"banner_found": True, "status": "banner", "banner": "220 FTP ready"},
                "3306": {"banner_found": False, "status": "no_banner"},
                "3389": {"banner_found": False, "status": "no_banner"},
            }
        }

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir), active=True, with_tools=True),
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool), patch(
                "hacker_soft.modules.projectdiscovery.collect_port_banners",
                return_value=banner_checks,
            ), patch(
                "hacker_soft.modules.projectdiscovery.collect_host_infrastructure",
                return_value={},
            ):
                ProjectDiscoveryModule()._naabu(context, result)

        risky = next(
            finding for finding in result.findings
            if finding.title == "Потенциально опасные сетевые сервисы доступны из интернета"
        )
        host_evidence = risky.evidence["hosts"]["example.com"]
        self.assertIn("21", host_evidence)
        self.assertEqual(host_evidence["21"]["banner"], "220 FTP ready")
        self.assertNotIn("3306", host_evidence)
        self.assertNotIn("3389", host_evidence)

    def test_risky_port_on_third_party_hosting_lowers_confidence(self):
        def fake_run_tool(_args, **_kwargs):
            return 0, '{"host":"example.com","port":21}', ""

        banner_checks = {"example.com": {"21": {"banner_found": True, "status": "banner", "banner": "220 hoster FTP"}}}
        infrastructure = {
            "example.com": {"ip": "10.0.0.1", "ptr": "srv12.shared-hoster.net", "third_party_hosting": True}
        }

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir), active=True, with_tools=True),
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool), patch(
                "hacker_soft.modules.projectdiscovery.collect_port_banners",
                return_value=banner_checks,
            ), patch(
                "hacker_soft.modules.projectdiscovery.collect_host_infrastructure",
                return_value=infrastructure,
            ):
                ProjectDiscoveryModule()._naabu(context, result)

        risky = next(
            finding for finding in result.findings
            if finding.title == "Потенциально опасные сетевые сервисы доступны из интернета"
        )
        self.assertEqual(risky.confidence, Confidence.MEDIUM)
        self.assertIn("внешнему хостингу", risky.impact)
        self.assertEqual(risky.evidence["infrastructure"], infrastructure)


class FindingStructureTests(TestCase):
    def header_finding(self, url: str, missing: list[str]) -> Finding:
        return Finding(
            module="http_probe",
            title="Не хватает стандартных браузерных security headers",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            target=url,
            evidence={"missing": missing},
        )

    def test_same_problem_on_many_hosts_becomes_one_finding(self):
        results = [
            ModuleResult(
                module="http_probe",
                findings=[
                    self.header_finding("https://a.example.com/", ["content-security-policy"]),
                    self.header_finding("https://b.example.com/", ["referrer-policy"]),
                    self.header_finding("https://c.example.com/", ["referrer-policy"]),
                ],
            )
        ]

        findings = collect_findings(results)

        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].all_targets), 3)
        self.assertEqual(findings[0].evidence["affected_count"], 3)
        self.assertIn("https://a.example.com/", findings[0].evidence["by_target"])

    def test_identical_duplicate_on_the_same_target_is_dropped(self):
        results = [
            ModuleResult(
                module="http_probe",
                findings=[
                    self.header_finding("https://a.example.com/", ["referrer-policy"]),
                    self.header_finding("https://a.example.com/", ["referrer-policy"]),
                ],
            )
        ]

        findings = collect_findings(results)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].all_targets, ["https://a.example.com/"])

    def test_inventory_and_diagnostics_stay_out_of_problem_counters(self):
        results = [
            ModuleResult(
                module="http_probe",
                findings=[
                    self.header_finding("https://a.example.com/", ["referrer-policy"]),
                    Finding(
                        module="http_probe",
                        title="HTTP-заголовки раскрывают технологию или версию",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        category=Category.INVENTORY,
                        target="https://a.example.com/",
                    ),
                    Finding(
                        module="dork_builder",
                        title="Нужна ручная проверка Google/Bing dorks",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        category=Category.DIAGNOSTIC,
                        target="example.com",
                    ),
                ],
            )
        ]

        findings = collect_findings(results)

        self.assertEqual(len(issues(findings)), 1)
        self.assertEqual(len(inventory(findings)), 1)
        self.assertEqual(len(diagnostics(findings)), 1)
        self.assertEqual(dict(severity_counter(issues(findings))), {"low": 1})

    def test_report_separates_problems_from_context(self):
        context = ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("/tmp/test"), active=True),
        )
        results = [
            ModuleResult(
                module="http_probe",
                findings=[
                    self.header_finding("https://a.example.com/", ["referrer-policy"]),
                    Finding(
                        module="projectdiscovery",
                        title="Подтвержденные открытые порты",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        category=Category.INVENTORY,
                        target="example.com",
                    ),
                ],
            )
        ]
        findings = collect_findings(results)
        summary = severity_counter(issues(findings))

        html = render_html(context, results, findings, summary)
        markdown = render_markdown(context, results, findings, summary)

        self.assertIn("<h2>Проблемы к исправлению (1)</h2>", html)
        self.assertIn("<h2>Инвентарь и контекст (1)</h2>", html)
        self.assertIn("Проблем к исправлению: `1`", markdown)
        self.assertIn("## Инвентарь и контекст", markdown)
        self.assertIn("Подтвержденные открытые порты", markdown)

    def test_unverified_dorks_are_listed_separately(self):
        result = ModuleResult(
            module="dork_builder",
            artifacts={
                "dorks": [],
                "auto_dork_summary": [
                    {"title": "Дампы баз данных", "result_count": 0, "errors": ["bing: капча"], "status": "unverified"},
                ],
                "unverified_dorks": [
                    {
                        "title": "Дампы баз данных",
                        "query": "site:example.com ext:sql",
                        "google": "https://google.test/sql",
                        "bing": "https://bing.test/sql",
                        "duckduckgo": "https://duck.test/sql",
                        "blocked_engines": ["bing", "google"],
                        "skipped_engines": [],
                    }
                ],
            },
        )

        html = render_dork_html([result])

        self.assertIn("Непроверенные дорки (1)", html)
        self.assertIn("site:example.com ext:sql", html)
        self.assertIn("bing, google", html)
        self.assertIn("не проверено из-за блокировок 1", html)


class KatanaStreamTests(TestCase):
    def test_endpoints_beyond_the_limit_are_reported_as_truncated(self):
        with TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "katana-output.jsonl"
            output.write_text(
                "\n".join(
                    json.dumps({"request": {"endpoint": f"https://example.com/page-{index}"}})
                    for index in range(10)
                )
                + "\n",
                encoding="utf-8",
            )

            endpoints, stats = stream_katana_endpoints("", output, "example.com", limit=4)

        self.assertEqual(len(endpoints), 4)
        self.assertTrue(stats["truncated"])

    def test_foreign_hosts_are_skipped(self):
        with TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "katana-output.jsonl"
            output.write_text(
                json.dumps({"request": {"endpoint": "https://other.test/page"}}) + "\n"
                + json.dumps({"request": {"endpoint": "https://app.example.com/page"}}) + "\n",
                encoding="utf-8",
            )

            endpoints, stats = stream_katana_endpoints("", output, "example.com")

        self.assertEqual(endpoints, {"https://app.example.com/page"})
        self.assertFalse(stats["truncated"])


class NucleiBatchTests(TestCase):
    def run_nuclei(self, live_hosts, fake_run_tool):
        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir)),
                live_hosts=set(live_hosts),
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool), patch_nuclei_templates():
                ProjectDiscoveryModule()._nuclei(context, result)
            merged = (Path(tmpdir) / "nuclei-output.jsonl").read_text(encoding="utf-8")
        return result, merged

    def test_targets_are_split_by_host_batch_and_severity(self):
        calls = []

        def fake_run_tool(args, **_kwargs):
            targets = Path(args[args.index("-list") + 1]).read_text(encoding="utf-8").split()
            calls.append((args[args.index("-severity") + 1], len(targets)))
            return 0, "", ""

        hosts = [f"https://host{index}.example.com" for index in range(20)]
        result, _ = self.run_nuclei(hosts, fake_run_tool)

        self.assertEqual(
            calls,
            [("critical,high", 15), ("critical,high", 5), ("medium,low", 15), ("medium,low", 5)],
        )
        self.assertEqual(result.artifacts["nuclei_batches"]["planned"], 4)
        self.assertEqual(result.artifacts["nuclei_batches"]["completed"], 4)
        self.assertEqual(result.errors, [])

    def test_findings_from_earlier_batches_survive_a_later_timeout(self):
        def fake_run_tool(args, **_kwargs):
            severity = args[args.index("-severity") + 1]
            if severity != "critical,high":
                return 124, "", "context deadline exceeded"
            output_path = Path(args[args.index("-jsonl-export") + 1])
            output_path.write_text(
                '{"template-id":"cve-2024-1234","matched-at":"https://app.example.com",'
                '"info":{"name":"Critical RCE","severity":"critical"}}\n',
                encoding="utf-8",
            )
            return 0, "", ""

        result, merged = self.run_nuclei(["https://app.example.com"], fake_run_tool)

        self.assertEqual(result.artifacts["nuclei_findings"], 1)
        self.assertEqual(result.findings[0].severity, Severity.CRITICAL)
        self.assertIn("частичные находки сохранены", result.errors[0])
        self.assertIn("выполнено 1 из 2 батчей", result.errors[0])
        self.assertIn("cve-2024-1234", merged)

    def test_every_batch_writes_into_the_merged_output(self):
        def fake_run_tool(args, **_kwargs):
            severity = args[args.index("-severity") + 1]
            template = "critical-template" if severity == "critical,high" else "low-template"
            output_path = Path(args[args.index("-jsonl-export") + 1])
            output_path.write_text(
                f'{{"template-id":"{template}","matched-at":"https://app.example.com",'
                f'"info":{{"name":"{template}","severity":"info"}}}}\n',
                encoding="utf-8",
            )
            return 0, "", ""

        result, merged = self.run_nuclei(["https://app.example.com"], fake_run_tool)

        self.assertEqual(result.artifacts["nuclei_findings"], 2)
        self.assertIn("critical-template", merged)
        self.assertIn("low-template", merged)


class NaabuPortConfidenceTests(TestCase):
    def run_naabu(self, ports, banner_checks, accept_all=None):
        def fake_run_tool(_args, **_kwargs):
            stdout = "\n".join(f'{{"host":"example.com","port":{port}}}' for port in ports)
            return 0, stdout, ""

        with TemporaryDirectory() as tmpdir:
            context = ScanContext(
                target=Target(raw="example.com", domain="example.com"),
                config=ScanConfig(out_dir=Path(tmpdir), active=True, with_tools=True),
            )
            result = ModuleResult(module="projectdiscovery")
            with patch("hacker_soft.modules.projectdiscovery.run_tool", fake_run_tool), patch(
                "hacker_soft.modules.projectdiscovery.collect_port_banners",
                return_value=banner_checks,
            ) as banners, patch(
                "hacker_soft.modules.projectdiscovery.probe_accept_all_host",
                return_value=accept_all,
            ), patch(
                "hacker_soft.modules.projectdiscovery.collect_host_infrastructure",
                return_value={},
            ):
                ProjectDiscoveryModule()._naabu(context, result)
        return context, result, banners

    def test_only_banner_confirmed_ports_become_assets(self):
        banner_checks = {
            "example.com": {
                "21": {"banner_found": True, "status": "banner", "banner": "220 FTP ready"},
                "3306": {"banner_found": False, "status": "no_banner"},
                "3389": {"banner_found": False, "status": "no_banner"},
            }
        }

        context, result, _ = self.run_naabu([21, 3306, 3389], banner_checks)

        self.assertEqual(context.open_ports, {"example.com": {21}})
        self.assertEqual(result.artifacts["confirmed_ports"], {"example.com": [21]})
        self.assertEqual(result.artifacts["open_ports_without_banners"], {"example.com": [3306, 3389]})
        self.assertEqual(result.artifacts["naabu_reported_ports"], 3)

    def test_ports_confirmed_after_client_probe_are_counted(self):
        banner_checks = {
            "example.com": {
                "8080": {"banner_found": True, "status": "banner_after_probe", "banner": "HTTP/1.0 200 OK"},
            }
        }

        context, result, _ = self.run_naabu([8080], banner_checks)

        self.assertEqual(context.open_ports, {"example.com": {8080}})
        self.assertEqual(result.artifacts["confirmed_port_count"], 1)

    def test_accept_all_host_keeps_every_port_out_of_assets(self):
        ports = list(range(1, 41))

        context, result, banners = self.run_naabu(ports, {})

        self.assertEqual(context.open_ports, {})
        self.assertEqual(result.artifacts["confirmed_port_count"], 0)
        self.assertEqual(result.artifacts["unconfirmed_port_count"], 40)
        self.assertEqual(result.artifacts["naabu_noisy_hosts"]["example.com"]["reason"], "too_many_open_ports")
        banners.assert_not_called()

    def test_noisy_host_never_produces_risky_service_finding(self):
        ports = sorted({21, 3306, 5432, 6379, 27017} | set(range(100, 140)))

        _, result, _ = self.run_naabu(ports, {})

        titles = [finding.title for finding in result.findings]
        self.assertIn("Результат port scan выглядит шумным и требует перепроверки", titles)
        self.assertNotIn("Потенциально опасные сетевые сервисы доступны из интернета", titles)
        self.assertNotIn("Подтвержденные открытые порты", titles)


class ExposurePathsTests(TestCase):
    def build_context(self):
        return ScanContext(
            target=Target(raw="example.com", domain="example.com"),
            config=ScanConfig(out_dir=Path("reports"), active=True),
        )

    def run_module(self, fake_http_get):
        with patch("hacker_soft.modules.exposure_paths.http_get", fake_http_get):
            return ExposurePathsModule().run(self.build_context())

    def test_owa_login_redirect_is_not_reported_as_exposed_path(self):
        def fake_http_get(url, _timeout=10, _max_bytes=16384):
            final = f"https://example.com/owa/auth/logon.aspx?url={quote(url, safe='')}&reason=0"
            return HttpResponse(
                url=final,
                status=200,
                headers={"content-type": "text/html; charset=utf-8"},
                body_sample='<html><title>Outlook</title><input type="password" name="passwd"></html>',
            )

        result = self.run_module(fake_http_get)

        self.assertEqual([f for f in result.findings if f.severity != Severity.INFO], [])
        self.assertEqual(result.artifacts["confirmed"], 0)
        self.assertIn("redirected", result.artifacts["rejected_reasons"])

    def test_soft_404_page_is_not_reported_as_exposed_path(self):
        def fake_http_get(url, _timeout=10, _max_bytes=16384):
            return HttpResponse(
                url=url,
                status=200,
                headers={"content-type": "text/html; charset=utf-8"},
                body_sample="<html><title>Страница не найдена</title><body>Ничего не найдено</body></html>",
            )

        result = self.run_module(fake_http_get)

        self.assertEqual(result.artifacts["confirmed"], 0)
        self.assertIn("baseline_match", result.artifacts["rejected_reasons"])
        self.assertTrue(result.artifacts["catch_all_origins"])

    def test_real_env_file_with_secrets_is_reported_as_high(self):
        def fake_http_get(url, _timeout=10, _max_bytes=16384):
            if url == "https://example.com/.env":
                return HttpResponse(
                    url=url,
                    status=200,
                    headers={"content-type": "text/plain"},
                    body_sample="APP_ENV=production\nAWS_SECRET_ACCESS_KEY=abc123\nDB_PASSWORD=hunter2\n",
                )
            return HttpResponse(url=url, status=404, headers={}, body_sample="not found")

        result = self.run_module(fake_http_get)

        findings = [f for f in result.findings if f.severity != Severity.INFO]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].target, "https://example.com/.env")
        self.assertIn("aws_secret_access_key", findings[0].evidence["markers"])

    def test_html_page_served_for_backup_zip_is_rejected_by_content_signature(self):
        def fake_http_get(url, _timeout=10, _max_bytes=16384):
            if url.endswith("/backup.zip"):
                return HttpResponse(
                    url=url,
                    status=200,
                    headers={"content-type": "text/html; charset=utf-8"},
                    body_sample="<html><body>Файл недоступен для скачивания</body></html>",
                )
            return HttpResponse(url=url, status=404, headers={}, body_sample="not found")

        result = self.run_module(fake_http_get)

        self.assertEqual(result.artifacts["confirmed"], 0)
        self.assertIn("content_mismatch", result.artifacts["rejected_reasons"])

    def test_real_zip_archive_is_reported_by_magic_bytes(self):
        def fake_http_get(url, _timeout=10, _max_bytes=16384):
            if url == "https://example.com/backup.zip":
                return HttpResponse(
                    url=url,
                    status=200,
                    headers={"content-type": "application/octet-stream"},
                    body_sample="PK\x03\x04binary",
                    body_bytes=b"PK\x03\x04binary",
                )
            return HttpResponse(url=url, status=404, headers={}, body_sample="not found")

        result = self.run_module(fake_http_get)

        findings = [f for f in result.findings if f.severity != Severity.INFO]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(findings[0].target, "https://example.com/backup.zip")


if __name__ == "__main__":
    main()
