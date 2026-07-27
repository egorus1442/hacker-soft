from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from shlex import quote
from threading import Lock


class ScanLogger:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def info(self, message: str) -> None:
        self.write("INFO", message)

    def error(self, message: str) -> None:
        self.write("ERROR", message)

    def command_start(self, args: list[str], timeout: int, input_lines: int | None = None) -> None:
        suffix = f", input_lines={input_lines}" if input_lines is not None else ""
        self.info(f"command start: {format_command(args)} timeout={timeout}s{suffix}")

    def command_end(self, args: list[str], code: int, elapsed: float, stdout_len: int, stderr_sample: str) -> None:
        sample = f" stderr={stderr_sample!r}" if stderr_sample else ""
        self.info(
            f"command end: {format_command(args)} code={code} elapsed={elapsed:.1f}s stdout_len={stdout_len}{sample}"
        )

    def write(self, level: str, message: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        line = f"{timestamp} {level} {message}\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)


def format_command(args: list[str]) -> str:
    return " ".join(quote(str(arg)) for arg in args)

