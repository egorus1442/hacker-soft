from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core.models import ScanConfig
from .core.report import flatten_findings
from .scanner import scan
from .tooling import render_tool_inventory


TOKEN_ENV = "HACKER_SOFT_TG_TOKEN"
ALLOWED_IDS_ENV = "HACKER_SOFT_TG_ALLOWED_IDS"
PROXY_ENV = "HACKER_SOFT_TG_PROXY"
START_ANALYSIS_TEXT = "Запустить анализ"


HELP_TEXT = """Привет. Я бот для автоматизированного defensive-пентеста внешней поверхности.

Нажми «Запустить анализ» или просто отправь домен, например: example.com.

Я сам запущу полный анализ: поддомены, DNS/почта, HTTP-сервисы, TLS, порты с проверкой баннеров, endpoints, nuclei, чувствительные пути и Google Dorking. Все результаты соберу в один HTML-отчет.

Автопроверка dorks включена всегда: бот проверяет поисковую выдачу и скрывает пустые dorks, где результатов не нашлось."""


class TelegramClient:
    def __init__(self, token: str, proxy_url: str | None = None):
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.proxy_url = proxy_url.strip() if proxy_url else None
        if self.proxy_url:
            proxy_handler = urllib.request.ProxyHandler({"http": self.proxy_url, "https": self.proxy_url})
            self.opener = urllib.request.build_opener(proxy_handler)
        else:
            self.opener = urllib.request.build_opener()

    def request_json(self, method: str, payload: dict[str, Any] | None = None, timeout: int = 60) -> dict[str, Any]:
        data = urllib.parse.urlencode(payload or {}).encode()
        request = urllib.request.Request(f"{self.base_url}/{method}", data=data)
        with self.opener.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def get_updates(self, offset: int | None, timeout: int = 30) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"timeout": timeout, "allowed_updates": json.dumps(["message"])}
        if offset is not None:
            payload["offset"] = offset
        data = self.request_json("getUpdates", payload=payload, timeout=timeout + 10)
        return data.get("result", [])

    def send_message(self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": "true",
        }
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        self.request_json("sendMessage", payload)

    def send_chat_action(self, chat_id: int, action: str) -> None:
        self.request_json("sendChatAction", {"chat_id": chat_id, "action": action}, timeout=20)

    def send_document(self, chat_id: int, path: Path, caption: str) -> None:
        boundary = f"----hacker-soft-{int(time.time() * 1000)}"
        body = bytearray()
        fields = {
            "chat_id": str(chat_id),
            "caption": caption,
        }
        for name, value in fields.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            body.extend(str(value).encode("utf-8"))
            body.extend(b"\r\n")

        filename = path.name
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            (
                f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
                "Content-Type: text/html; charset=utf-8\r\n\r\n"
            ).encode()
        )
        body.extend(path.read_bytes())
        body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode())

        request = urllib.request.Request(
            f"{self.base_url}/sendDocument",
            data=bytes(body),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        with self.opener.open(request, timeout=120) as response:
            json.loads(response.read().decode("utf-8"))


class HackerSoftBot:
    def __init__(self, client: TelegramClient, reports_dir: Path, allowed_ids: set[int]):
        self.client = client
        self.reports_dir = reports_dir
        self.allowed_ids = allowed_ids
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.active_scans: set[tuple[int, str]] = set()
        self.active_chats: dict[int, str] = {}
        self.lock = threading.Lock()

    def run_forever(self) -> None:
        offset: int | None = None
        print("Telegram bot started")
        while True:
            try:
                updates = self.client.get_updates(offset=offset, timeout=30)
                for update in updates:
                    offset = update["update_id"] + 1
                    self.handle_update(update)
            except KeyboardInterrupt:
                print("Stopping bot")
                return
            except Exception as exc:  # noqa: BLE001 - polling must survive transient Telegram/network errors.
                print(f"Polling error: {exc}")
                time.sleep(3)

    def handle_update(self, update: dict[str, Any]) -> None:
        message = update.get("message") or {}
        text = (message.get("text") or "").strip()
        chat = message.get("chat") or {}
        from_user = message.get("from") or {}
        chat_id = chat.get("id")
        user_id = from_user.get("id")
        if not chat_id or not user_id or not text:
            return

        if self.allowed_ids and int(user_id) not in self.allowed_ids:
            self.client.send_message(chat_id, "Доступ закрыт. Добавь свой Telegram user id в HACKER_SOFT_TG_ALLOWED_IDS.")
            return

        if text.startswith("/start") or text.startswith("/help"):
            self.client.send_message(chat_id, HELP_TEXT, reply_markup=main_keyboard())
            return
        if text.startswith("/tools"):
            self.client.send_message(chat_id, render_tool_inventory(), reply_markup=main_keyboard())
            return
        if text == START_ANALYSIS_TEXT:
            active_domain = self.get_active_domain(int(chat_id))
            if active_domain:
                self.client.send_message(
                    chat_id,
                    (
                        f"Сейчас уже идет анализ: {active_domain}\n"
                        "Новый анализ можно запустить только после того, как придет предыдущий отчет."
                    ),
                    reply_markup=main_keyboard(),
                )
                return
            self.client.send_message(
                chat_id,
                "Пришли домен компании, например: scriptor.tech",
                reply_markup=main_keyboard(),
            )
            return

        request = parse_scan_request(text) if text.startswith("/") else parse_domain_request(text)
        if request is None:
            self.client.send_message(
                chat_id,
                "Не похоже на домен. Пришли домен без лишнего текста, например: scriptor.tech",
                reply_markup=main_keyboard(),
            )
            return

        chat_id_int = int(chat_id)
        key = (chat_id_int, request["domain"])
        with self.lock:
            active_domain = self.active_chats.get(chat_id_int)
            if active_domain:
                self.client.send_message(
                    chat_id,
                    (
                        f"Сейчас уже идет анализ: {active_domain}\n"
                        "Новый анализ можно запустить только после того, как придет предыдущий отчет."
                    ),
                    reply_markup=main_keyboard(),
                )
                return
            if key in self.active_scans:
                self.client.send_message(chat_id, f"Анализ {request['domain']} уже идет. Дождись отчета.", reply_markup=main_keyboard())
                return
            self.active_scans.add(key)
            self.active_chats[chat_id_int] = request["domain"]

        self.client.send_message(
            chat_id,
            (
                f"Принял цель: {request['domain']}\n"
                "Запускаю автоматизированный пентест: recon, проверки уязвимостей, crawling и dorking. "
                "Все результаты соберу в один HTML-отчет.\n\n"
                f"Ориентир по времени: {estimate_wait_text(request)}."
            ),
            reply_markup=main_keyboard(),
        )
        self.executor.submit(self.run_scan_job, int(chat_id), key, request)

    def run_scan_job(self, chat_id: int, key: tuple[int, str], request: dict[str, Any]) -> None:
        started = time.time()
        domain = request["domain"]
        stop_progress = threading.Event()
        progress_thread = threading.Thread(
            target=self.send_progress_updates,
            args=(chat_id, domain, started, stop_progress),
            daemon=True,
        )
        progress_thread.start()
        try:
            self.client.send_chat_action(chat_id, "typing")
            out_dir = self.build_report_dir(chat_id, domain)
            config = ScanConfig(
                profile=request["profile"],
                active=request["active"],
                with_tools=request["with_tools"],
                heavy_tools=request["heavy_tools"],
                auto_dork_search=request["auto_dork_search"],
                max_dork_queries=request["max_dork_queries"],
                max_dork_results=request["max_dork_results"],
                timeout_seconds=request["timeout"],
                max_hosts=request["max_hosts"],
                out_dir=out_dir,
            )
            context, results, paths = scan(domain, config, company=request.get("company"))
            findings = flatten_findings(results)
            elapsed = int(time.time() - started)
            caption = (
                f"Готово: {context.target.domain}\n"
                f"Находок: {len(findings)}\n"
                f"Критично/высоко: {count_severity(findings, 'critical')}/{count_severity(findings, 'high')}\n"
                f"Время: {elapsed} сек."
            )
            self.client.send_chat_action(chat_id, "upload_document")
            self.client.send_document(chat_id, paths["html"], caption=caption)
            self.client.send_message(chat_id, "Готов к следующей проверке.", reply_markup=main_keyboard())
        except Exception as exc:  # noqa: BLE001
            self.client.send_message(chat_id, f"Анализ упал: {exc}", reply_markup=main_keyboard())
        finally:
            stop_progress.set()
            with self.lock:
                self.active_scans.discard(key)
                self.active_chats.pop(chat_id, None)

    def get_active_domain(self, chat_id: int) -> str | None:
        with self.lock:
            return self.active_chats.get(chat_id)

    def send_progress_updates(
        self,
        chat_id: int,
        domain: str,
        started: float,
        stop_event: threading.Event,
    ) -> None:
        checkpoints = [
            (180, "Анализ еще идет. Для глубокого режима это нормально: сейчас могут работать crawling, проверка портов или nuclei."),
            (420, "Все еще работаю над отчетом. Если домен отвечает медленно или nuclei проверяет много шаблонов, ожидание может растянуться."),
            (900, "Анализ идет дольше обычного, но процесс не потерян. Дождись HTML-отчета или перезапусти бота, если хочешь остановить текущую проверку."),
        ]
        for seconds, message in checkpoints:
            remaining = seconds - int(time.time() - started)
            if remaining > 0 and stop_event.wait(remaining):
                return
            if stop_event.is_set():
                return
            elapsed = int(time.time() - started)
            try:
                self.client.send_message(
                    chat_id,
                    f"{domain}\n{message}\nПрошло: {format_duration(elapsed)}.",
                    reply_markup=main_keyboard(),
                )
            except Exception as exc:  # noqa: BLE001
                print(f"Progress message failed: {exc}")

    def build_report_dir(self, chat_id: int, domain: str) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        safe_domain = re.sub(r"[^a-zA-Z0-9.-]+", "_", domain).strip("._") or "target"
        return self.reports_dir / str(chat_id) / f"{safe_domain}-{timestamp}"


def parse_domain_request(text: str) -> dict[str, Any] | None:
    domain = clean_domain(text)
    if not domain:
        return None
    return build_deep_request(domain)


def build_deep_request(domain: str) -> dict[str, Any]:
    return {
        "domain": domain,
        "profile": "deep",
        "active": True,
        "with_tools": True,
        "heavy_tools": False,
        "auto_dork_search": True,
        "max_dork_queries": 50,
        "max_dork_results": 50,
        "timeout": 12,
        "max_hosts": 250,
        "company": None,
    }


def estimate_wait_text(request: dict[str, Any]) -> str:
    if request.get("heavy_tools"):
        return "20-60 минут и больше"
    if request.get("with_tools"):
        return "обычно 10-30 минут, иногда дольше из-за nuclei, dorks или медленных внешних сервисов"
    return "обычно 1-5 минут"


def format_duration(seconds: int) -> str:
    minutes, rest = divmod(max(seconds, 0), 60)
    if minutes:
        return f"{minutes} мин {rest} сек"
    return f"{rest} сек"


def parse_scan_request(text: str) -> dict[str, Any] | None:
    parts = text.split()
    command = parts[0].split("@", 1)[0].lower()

    company = None

    if command in {"/scan", "/fast", "/deep", "/pentest"}:
        if len(parts) < 2:
            return None
        domain = parts[1]
        extra = parts[2:]
    else:
        domain = parts[0]
        extra = parts[1:]

    for item in extra:
        item_lower = item.lower()
        if item_lower.startswith("company="):
            company = item.split("=", 1)[1].strip() or None

    cleaned_domain = clean_domain(domain)
    if not cleaned_domain:
        return None

    request = build_deep_request(cleaned_domain)
    request["company"] = company
    return request


def main_keyboard() -> dict[str, Any]:
    return {
        "keyboard": [[{"text": START_ANALYSIS_TEXT}]],
        "resize_keyboard": True,
        "one_time_keyboard": False,
        "input_field_placeholder": "Нажми кнопку или отправь домен",
    }


def clean_domain(value: str) -> str | None:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0].strip(".")
    if value.startswith("www."):
        value = value[4:]
    if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", value):
        return value
    return None


def count_severity(findings: list, severity: str) -> int:
    return sum(1 for finding in findings if finding.severity.value == severity)


def parse_allowed_ids(raw: str | None) -> set[int]:
    if not raw:
        return set()
    allowed = set()
    for item in raw.split(","):
        item = item.strip()
        if item:
            allowed.add(int(item))
    return allowed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hacker-soft-bot")
    parser.add_argument("--token-env", default=TOKEN_ENV, help="Environment variable with Telegram bot token")
    parser.add_argument("--proxy-env", default=PROXY_ENV, help="Environment variable with proxy URL for Telegram API only")
    parser.add_argument("--reports-dir", type=Path, default=Path("reports/telegram"))
    parser.add_argument("--allow-anyone", action="store_true", help="Allow any Telegram user to run scans")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    token = os.getenv(args.token_env)
    if not token:
        raise SystemExit(f"Нет токена. Установи переменную окружения {args.token_env}.")
    if args.allow_anyone:
        allowed_ids = set()
        print("Telegram allowlist disabled: any Telegram user can run scans")
    else:
        allowed_ids = parse_allowed_ids(os.getenv(ALLOWED_IDS_ENV))
        if not allowed_ids:
            raise SystemExit(
                f"Нет allowlist. Установи {ALLOWED_IDS_ENV} со своим Telegram user id "
                "или запусти с --allow-anyone для открытого режима."
            )
    proxy_url = os.getenv(args.proxy_env)
    if proxy_url:
        print(f"Telegram API proxy enabled from {args.proxy_env}")
    HackerSoftBot(TelegramClient(token, proxy_url=proxy_url), args.reports_dir, allowed_ids).run_forever()


if __name__ == "__main__":
    main()
