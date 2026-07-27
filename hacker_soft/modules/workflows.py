from __future__ import annotations

import os
from pathlib import Path

from hacker_soft.core.models import Category, Confidence, Finding, ModuleResult, ScanContext, Severity
from hacker_soft.core.module import ScannerModule
from hacker_soft.core.net import run_tool


class HeavyWorkflowModule(ScannerModule):
    name = "heavy_workflows"
    passive = False

    def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(module=self.name)
        if not context.config.heavy_tools:
            result.artifacts["skipped"] = "требуется --heavy-tools"
            return result

        self._reconftw(context, result)
        self._rengine_hint(result)
        return result

    def _reconftw(self, context: ScanContext, result: ModuleResult) -> None:
        executable = find_reconftw()
        if not executable:
            result.errors.append("reconFTW не найден: установи reconftw/reconftw.sh и добавь в PATH")
            return

        out_dir = context.config.out_dir / "reconftw"
        out_dir.mkdir(parents=True, exist_ok=True)
        args = [
            executable,
            "-d",
            context.target.domain,
            "-o",
            str(out_dir),
            "-r",
        ]
        code, stdout, stderr = run_tool(args, timeout=7200, logger=context.logger)
        result.artifacts["reconftw_output_dir"] = str(out_dir)
        result.artifacts["reconftw_stdout_sample"] = stdout[-4000:]
        if code != 0:
            result.errors.append(f"reconFTW завершился ошибкой: {stderr.strip()[-1000:]}")
            return

        imported = import_reconftw_hosts(out_dir, context.target.domain)
        context.subdomains.update(imported)
        result.artifacts["reconftw_imported_hosts"] = len(imported)
        result.findings.append(
            Finding(
                module=self.name,
                title="reconFTW workflow завершен",
                severity=Severity.INFO,
                category=Category.DIAGNOSTIC,
                confidence=Confidence.MEDIUM,
                target=context.target.domain,
                evidence={"output_dir": str(out_dir), "imported_hosts": len(imported)},
                recommendation="Открой артефакты reconFTW, проверь найденные assets и перенеси важные находки в план исправлений.",
            )
        )

    def _rengine_hint(self, result: ModuleResult) -> None:
        rengine_url = os.getenv("RENGINE_URL")
        if not rengine_url:
            result.artifacts["rengine"] = "не настроен; для self-hosted reNgine укажи RENGINE_URL и используй его dashboard/API отдельно"
            return
        result.findings.append(
            Finding(
                module=self.name,
                title="reNgine self-hosted endpoint настроен",
                severity=Severity.INFO,
                category=Category.DIAGNOSTIC,
                confidence=Confidence.LOW,
                target=rengine_url,
                evidence={"rengine_url": rengine_url},
                recommendation="Используй reNgine как отдельный dashboard, а в этот бот импортируй финальные JSON/артефакты через будущий API-адаптер.",
            )
        )


def find_reconftw() -> str | None:
    for candidate in ("reconftw", "reconftw.sh"):
        code, _, _ = run_tool([candidate, "-h"], timeout=10)
        if code != 127:
            return candidate
    return None


def import_reconftw_hosts(out_dir: Path, domain: str) -> set[str]:
    hosts: set[str] = set()
    for path in out_dir.rglob("*"):
        if not path.is_file() or path.stat().st_size > 5_000_000:
            continue
        if path.suffix.lower() not in {".txt", ".log", ".csv"}:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for token in content.replace(",", "\n").replace(" ", "\n").splitlines():
            host = token.strip().lower().strip(".")
            if host == domain or host.endswith("." + domain):
                hosts.add(host)
    return hosts
