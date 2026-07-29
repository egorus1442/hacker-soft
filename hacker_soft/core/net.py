from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import tempfile
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
    body_bytes: bytes = b""


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
                body_bytes=body,
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
            body_bytes=body,
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


LEGACY_TLS_VERSIONS = ("TLSv1", "TLSv1.1")


def tls_version_state(host: str, version: str, port: int = 443, timeout: int = 8) -> dict[str, str]:
    """Probe one protocol version explicitly.

    A default context always negotiates the newest version, so it can never prove that a
    legacy protocol is disabled. Modern OpenSSL builds also refuse TLS 1.0/1.1 locally,
    and that case must be reported as unknown instead of as a clean result.
    """
    try:
        tls_version = getattr(ssl.TLSVersion, version.replace(".", "_"))
    except AttributeError:
        return {"state": "unknown", "detail": f"неизвестная версия {version}"}

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = tls_version
        context.maximum_version = tls_version
    except (ValueError, OSError) as exc:
        return {"state": "unknown", "detail": f"локальный OpenSSL не умеет проверять {version}: {exc}"}
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return {"state": "supported", "detail": ssock.version() or version}
    except ssl.SSLError as exc:
        message = str(exc)
        if "no protocols available" in message or "unsupported protocol" in message.lower():
            fallback = _tls_version_state_openssl_cli(host, version, port, timeout)
            if fallback is not None:
                return fallback
            return {"state": "unknown", "detail": f"локальный OpenSSL отключил {version}: {message}"}
        return {"state": "rejected", "detail": message}
    except OSError as exc:
        return {"state": "unknown", "detail": str(exc)}


_OPENSSL_VERSION_FLAGS = {"TLSv1": "-tls1", "TLSv1.1": "-tls1_1"}


def _tls_version_state_openssl_cli(host: str, version: str, port: int, timeout: int) -> dict[str, str] | None:
    """Best-effort fallback when Python's ssl module (bound by the system-wide OpenSSL
    crypto policy) refuses to even attempt a legacy protocol version.

    Runs the openssl CLI with an empty OPENSSL_CONF, which drops the distro's
    `MinProtocol` policy override for this one subprocess call without touching the
    long-lived Python process. This can still fail (e.g. openssl missing, or its own
    compiled-in defaults also reject the version) - callers must treat None as
    "no better answer" and keep their own unknown state.
    """
    flag = _OPENSSL_VERSION_FLAGS.get(version)
    if not flag:
        return None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False) as empty_conf:
            empty_conf_path = empty_conf.name
        try:
            completed = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:{port}", flag, "-cipher", "ALL:@SECLEVEL=0"],
                input="",
                text=True,
                capture_output=True,
                timeout=timeout,
                env={**os.environ, "OPENSSL_CONF": empty_conf_path},
                check=False,
            )
        finally:
            try:
                os.unlink(empty_conf_path)
            except OSError:
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    output = (completed.stdout or "") + (completed.stderr or "")
    if "Protocol  :" in output or "Protocol:" in output:
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Protocol"):
                negotiated = stripped.split(":", 1)[1].strip()
                if negotiated and negotiated != "0":
                    return {"state": "supported", "detail": negotiated}
    lowered = output.lower()
    if "no protocols available" in lowered or "unsupported protocol" in lowered or "wrong version number" in lowered:
        return {"state": "rejected", "detail": "openssl CLI: сервер отверг устаревший протокол"}
    return None


def tls_validation_state(host: str, port: int = 443, timeout: int = 8) -> dict[str, str]:
    """Check what a browser would check: trusted chain plus matching hostname."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return {"state": "valid", "detail": ""}
    except ssl.SSLCertVerificationError as exc:
        reason = str(exc.verify_message or exc)
        lower = reason.lower()
        if "hostname mismatch" in lower or "doesn't match" in lower:
            kind = "hostname_mismatch"
        elif "expired" in lower:
            kind = "expired"
        elif "self signed" in lower or "self-signed" in lower:
            kind = "self_signed"
        elif "unable to get local issuer" in lower or "unable to verify" in lower:
            kind = "untrusted_chain"
        else:
            kind = "verification_failed"
        return {"state": kind, "detail": reason}
    except ssl.SSLError as exc:
        return {"state": "handshake_failed", "detail": str(exc)}
    except OSError as exc:
        return {"state": "unreachable", "detail": str(exc)}


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
