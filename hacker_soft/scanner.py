from __future__ import annotations

import time
from collections.abc import Iterable

from .core.logging import ScanLogger
from .core.models import ModuleResult, ScanConfig, ScanContext, Target
from .core.net import is_probably_domain, normalize_domain
from .core.report import write_reports
from .modules.ct_subdomains import CertificateTransparencyModule
from .modules.amass import AmassModule
from .modules.document_links import DocumentLinksModule
from .modules.dns_email import DnsEmailModule
from .modules.dorks import DorkBuilderModule
from .modules.exposure_paths import ExposurePathsModule
from .modules.http_probe import HttpProbeModule
from .modules.projectdiscovery import ProjectDiscoveryModule
from .modules.tls import TlsModule
from .modules.urlscan import UrlscanModule
from .modules.workflows import HeavyWorkflowModule


def default_modules(profile: str) -> list:
    modules = [
        DnsEmailModule(),
        CertificateTransparencyModule(),
        UrlscanModule(),
        DorkBuilderModule(),
    ]
    if profile == "fast":
        return modules
    if profile in {"standard", "deep"}:
        modules.extend([HttpProbeModule(), TlsModule()])
    if profile == "deep":
        modules.extend([ProjectDiscoveryModule(), DocumentLinksModule(), AmassModule(), ExposurePathsModule(), HeavyWorkflowModule()])
    else:
        modules.extend([ProjectDiscoveryModule(), DocumentLinksModule(), AmassModule(), ExposurePathsModule()])
    return modules


def scan(raw_target: str, config: ScanConfig, company: str | None = None) -> tuple[ScanContext, list[ModuleResult], dict]:
    domain = normalize_domain(raw_target)
    if not is_probably_domain(domain):
        raise ValueError(f"Unsupported target: {raw_target!r}. Provide a domain like example.com.")

    config.out_dir.mkdir(parents=True, exist_ok=True)
    logger = ScanLogger(config.out_dir / "scan.log")
    context = ScanContext(target=Target(raw=raw_target, domain=domain, company=company), config=config, logger=logger)
    logger.info(
        f"scan start target={domain} profile={config.profile} active={config.active} "
        f"with_tools={config.with_tools} heavy_tools={config.heavy_tools}"
    )
    results = run_modules(context, default_modules(config.profile))
    paths = write_reports(context, results)
    logger.info(
        f"scan complete findings={sum(len(result.findings) for result in results)} "
        f"subdomains={len(context.subdomains)} live_hosts={len(context.live_hosts)} endpoints={len(context.endpoints)}"
    )
    return context, results, paths


def run_modules(context: ScanContext, modules: Iterable) -> list[ModuleResult]:
    results: list[ModuleResult] = []
    for module in modules:
        if not context.config.active and not module.passive:
            results.append(ModuleResult(module=module.name, artifacts={"skipped": "требуется --active"}))
            continue
        started = time.monotonic()
        if context.logger:
            context.logger.info(f"module start: {module.name}")
        try:
            result = module.run(context)
            results.append(result)
            if context.logger:
                context.logger.info(
                    f"module end: {module.name} elapsed={time.monotonic() - started:.1f}s "
                    f"findings={len(result.findings)} errors={len(result.errors)} artifacts={list(result.artifacts.keys())}"
                )
        except Exception as exc:  # noqa: BLE001 - scanner should finish with module errors.
            results.append(ModuleResult(module=module.name, errors=[str(exc)]))
            if context.logger:
                context.logger.error(f"module failed: {module.name} elapsed={time.monotonic() - started:.1f}s error={exc}")
    return results
