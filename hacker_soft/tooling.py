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
    return [
        ToolInfo(
            name=name,
            command=command,
            purpose=purpose,
            installed=shutil.which(command) is not None or (command == "reconftw" and shutil.which("reconftw.sh") is not None),
            url=url,
        )
        for name, command, purpose, url in TOOLS
    ]


def render_tool_inventory() -> str:
    lines = ["Инструменты backend:"]
    for tool in tool_inventory():
        mark = "OK" if tool.installed else "нет"
        lines.append(f"- {mark} {tool.name}: {tool.purpose}")
    return "\n".join(lines)

