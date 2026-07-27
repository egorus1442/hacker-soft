from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolInfo:
    name: str
    command: str
    purpose: str
    installed: bool
    url: str
    ready: bool = True
    note: str = ""


TOOLS = [
    ("subfinder", "subfinder", "поиск поддоменов", "https://github.com/projectdiscovery/subfinder"),
    ("dnsx", "dnsx", "DNS-резолвинг и enrichment", "https://github.com/projectdiscovery/dnsx"),
    ("httpx", "httpx", "HTTP probing, titles, tech-detect", "https://github.com/projectdiscovery/httpx"),
    ("naabu", "naabu", "быстрый поиск открытых портов", "https://github.com/projectdiscovery/naabu"),
    ("katana", "katana", "краулинг endpoints", "https://github.com/projectdiscovery/katana"),
    ("nuclei", "nuclei", "template-based проверки", "https://github.com/projectdiscovery/nuclei"),
    ("amass", "amass", "attack-surface mapping", "https://github.com/owasp-amass/amass"),
    ("reconFTW", "reconftw", "тяжелый recon workflow", "https://github.com/six2dez/reconftw"),
]


def tool_inventory() -> list[ToolInfo]:
    tools = []
    for name, command, purpose, url in TOOLS:
        installed = shutil.which(command) is not None or (
            command == "reconftw" and shutil.which("reconftw.sh") is not None
        )
        ready, note = check_readiness(command, installed)
        tools.append(
            ToolInfo(
                name=name,
                command=command,
                purpose=purpose,
                installed=installed,
                url=url,
                ready=ready,
                note=note,
            )
        )
    return tools


def check_readiness(command: str, installed: bool) -> tuple[bool, str]:
    """An installed binary is not enough: nuclei without templates scans nothing."""
    if not installed:
        return False, "не установлен"
    if command != "nuclei":
        return True, ""

    from .modules.projectdiscovery import find_nuclei_templates

    templates = find_nuclei_templates()
    if templates["ready"]:
        return True, f"шаблоны: {templates['path']}"
    return False, "шаблоны не установлены, запусти 'nuclei -update-templates'"


def render_tool_inventory() -> str:
    lines = ["Инструменты backend:"]
    for tool in tool_inventory():
        if not tool.installed:
            mark = "нет"
        elif not tool.ready:
            mark = "НЕ ГОТОВ"
        else:
            mark = "OK"
        suffix = f" ({tool.note})" if tool.note else ""
        lines.append(f"- {mark} {tool.name}: {tool.purpose}{suffix}")
    return "\n".join(lines)
