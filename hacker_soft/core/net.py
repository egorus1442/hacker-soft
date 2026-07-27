from __future__ import annotations

import json
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .logging import ScanLogger


USER_AGENT = "hacker-soft/0.1 defensive scanner"


@dataclass
class HttpResponse:
    url: str
    status: int | None
    headers: dict[str, str]
    body_sample: str
    error: str | None = None


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        value = parsed.hostname or value
    value = value.strip(".")
    if value.startswith("www."):
        value = value[4:]
    return value


def is_probably_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    return all(ch in allowed for ch in value.lower())


def http_get(url: str, timeout: int = 10, max_bytes: int = 65536) -> HttpResponse:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(max_bytes)
            charset = response.headers.get_content_charset() or "utf-8"
            text = body.decode(charset, errors="replace")
            return HttpResponse(
                url=response.geturl(),
                status=response.status,
                headers={k.lower(): v for k, v in response.headers.items()},
                body_sample=text,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read(min(max_bytes, 8192))
        text = body.decode("utf-8", errors="replace")
        return HttpResponse(
            url=url,
            status=exc.code,
            headers={k.lower(): v for k, v in exc.headers.items()},
            body_sample=text,
            error=str(exc),
        )
    except Exception as exc:  # noqa: BLE001 - keep scanner resilient.
        return HttpResponse(url=url, status=None, headers={}, body_sample="", error=str(exc))


def fetch_json(url: str, timeout: int = 15) -> Any:
    response = http_get(url, timeout=timeout, max_bytes=2_000_000)
    if response.error and response.status is None:
        raise RuntimeError(response.error)
    return json.loads(response.body_sample)


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips = sorted({info[4][0] for info in infos})
    return ips


def run_tool(
    args: list[str],
    timeout: int = 60,
    input_text: str | None = None,
    logger: ScanLogger | None = None,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> tuple[int, str, str]:
    started = time.monotonic()
    if logger:
        input_lines = input_text.count("\n") if input_text else None
        logger.command_start(args, timeout=timeout, input_lines=input_lines)
    stdout_handle = None
    stderr_handle = None
    try:
        stdout_handle = stdout_path.open("w", encoding="utf-8", errors="replace") if stdout_path else subprocess.PIPE
        stderr_handle = stderr_path.open("w", encoding="utf-8", errors="replace") if stderr_path else subprocess.PIPE
        completed = subprocess.run(
            args,
            input=input_text,
            text=True,
            stdout=stdout_handle,
            stderr=stderr_handle,
            timeout=timeout,
            check=False,
        )
        if stdout_path:
            stdout_handle.close()
        if stderr_path:
            stderr_handle.close()
    except FileNotFoundError:
        if stdout_path and stdout_handle and not stdout_handle.closed:
            stdout_handle.close()
        if stderr_path and stderr_handle and not stderr_handle.closed:
            stderr_handle.close()
        write_capture(stdout_path, "")
        write_capture(stderr_path, f"{args[0]} not found")
        if logger:
            logger.command_end(args, code=127, elapsed=time.monotonic() - started, stdout_len=0, stderr_sample=f"{args[0]} not found")
        return 127, "", f"{args[0]} not found"
    except subprocess.TimeoutExpired as exc:
        if stdout_path and not stdout_handle.closed:
            stdout_handle.close()
        if stderr_path and not stderr_handle.closed:
            stderr_handle.close()
        stdout = as_text(exc.stdout)
        stderr = as_text(exc.stderr) or "timeout"
        if not stdout_path:
            write_capture(stdout_path, stdout)
        if not stderr_path:
            write_capture(stderr_path, stderr)
        if logger:
            logger.command_end(args, code=124, elapsed=time.monotonic() - started, stdout_len=len(stdout), stderr_sample=stderr[:500])
        return 124, stdout, stderr
    stdout = "" if stdout_path else (completed.stdout or "")
    stderr = "" if stderr_path else (completed.stderr or "")
    if not stdout_path:
        write_capture(stdout_path, stdout)
    if not stderr_path:
        write_capture(stderr_path, stderr)
    if logger:
        logger.command_end(
            args,
            code=completed.returncode,
            elapsed=time.monotonic() - started,
            stdout_len=len(stdout),
            stderr_sample=stderr[:500],
        )
    return completed.returncode, stdout, stderr


def as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def write_capture(path: Path | None, text: str) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def tls_certificate_summary(host: str, port: int = 443, timeout: int = 8) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "subject_alt_name": cert.get("subjectAltName", []),
                "cipher": ssock.cipher(),
                "version": ssock.version(),
            }
