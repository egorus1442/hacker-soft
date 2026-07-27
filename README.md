# hacker-soft

Модульный defensive-сканер для внешней поверхности активов, которыми ты владеешь.
Есть CLI и Telegram-бот. Отчеты генерируются в `HTML`, `JSON` и `Markdown`.
HTML-отчет содержит пояснения простым языком: что найдено, чем это грозит,
что делать, какие технические ошибки были во время сбора и какие артефакты
нужно перепроверить вручную.

Сканер намеренно не делает разрушительные вещи:

- без брутфорса
- без обхода авторизации
- без запуска эксплойтов
- без разрушительных payload'ов

Он собирает пассивный OSINT, поддомены, DNS/email security, HTTP/TLS-сигналы,
dorks, документы, endpoints, экспонированные пути, common ports и результаты
optional CLI-инструментов.

Важно: запускай сканирование только по своим доменам или по целям, на которые
есть явное разрешение.

## Установка

Минимальный локальный запуск самого сканера не требует runtime-зависимостей:

```bash
python3 -m hacker_soft tools
```

Тесты запускаются через `pytest`:

```bash
python3 -m pytest
```

Для удобства можно установить CLI entrypoints:

```bash
python3 -m pip install -e .
hacker-soft tools
```

## CLI

```bash
python3 -m hacker_soft scan example.com --out reports/example
```

Проверить, какие внешние инструменты уже установлены:

```bash
python3 -m hacker_soft tools
```

Быстрый пассивный запуск:

```bash
python3 -m hacker_soft scan example.com --profile fast --out reports/example-fast
```

Включить безопасные active checks:

```bash
python3 -m hacker_soft scan example.com --profile standard --active --with-tools --out reports/example-active
```

Автоматизированный defensive-пентест по своему домену: recon, безопасные проверки уязвимостей, nuclei, crawling и dorking:

```bash
python3 -m hacker_soft pentest example.com --out reports/example-pentest
```

`pentest` - это shortcut для полного сценария:

- `profile=deep`
- `--active`
- `--with-tools`
- `--auto-dork-search`
- `--max-dork-queries 50`
- `--max-dork-results 50`

Если нужны тяжелые внешние workflow, добавь `--heavy-tools`:

```bash
python3 -m hacker_soft pentest example.com --heavy-tools --out reports/example-pentest-heavy
```

Использовать optional tools, если они установлены:

```bash
python3 -m hacker_soft scan example.com --profile deep --active --with-tools --out reports/example-tools
```

Автоматически собрать и распарсить выдачу поисковиков и Common Crawl по dorks:

```bash
python3 -m hacker_soft scan example.com --profile deep --auto-dork-search --max-dork-queries 50 --out reports/example-dorks
```

Auto dork search пробует несколько источников: DuckDuckGo Lite, Yahoo, Google,
DuckDuckGo, Bing и Common Crawl для документов. Поисковики могут отвечать
`403`, `429`, CAPTCHA или timeout; такие события попадают в статус dorking,
но не считаются подтвержденными уязвимостями.

Тяжелые workflow-инструменты, например reconFTW:

```bash
python3 -m hacker_soft scan example.com --profile deep --active --with-tools --heavy-tools --out reports/example-heavy
```

## Отчеты и документы

Каждый запуск пишет:

- `report.html`
- `report.json`
- `report.md`
- `scan.log`
- дополнительные JSONL/MD/TXT артефакты модулей

HTML-отчет сейчас показывает блок `Публичные документы` перед блоком `Находки`.
Документы разделены на группы:

- документы, найденные на страницах сайта и через crawler;
- документы, найденные через dorks, с пометкой `DORK`;
- общий список документов.

Списки документов выводятся порциями с пагинацией. Ссылки кодируются так, чтобы
нормально открывались URL с пробелами и кириллицей. Проверка документов смотрит
HTTP-статус, финальный URL, `Content-Type` и первые байты файла, поэтому PDF/DOC/XLS
не считаются найденными только по расширению в ссылке.

Отчеты и временные результаты лежат в `reports/` и не коммитятся в git.

Отдельный скрипт для ручной проверки списка ссылок:

```bash
python3 -m pip install httpx
python3 scripts/check_document_links.py --input urls.txt --out-jsonl checked-documents.jsonl
```

Для этого скрипта нужен Python-пакет `httpx`.

## Telegram-бот

Токен не хранится в коде. Перед запуском положи его в переменную окружения:

```bash
export HACKER_SOFT_TG_TOKEN="токен_от_BotFather"
```

Рекомендуется ограничить запуск только своим Telegram user id:
По умолчанию бот не стартует без allowlist.

```bash
export HACKER_SOFT_TG_ALLOWED_IDS="123456789"
```

Запуск:

```bash
python3 -m hacker_soft.bot
```

Запуск через Docker:

```bash
export HACKER_SOFT_TG_TOKEN="токен_от_BotFather"
docker compose up --build bot
```

Текущий `docker-compose.yml` запускает bot-сервис с `--allow-anyone`.
Это удобно для локальной разработки, но небезопасно для публичного сервера.
Для закрытого режима убери `--allow-anyone` из `docker-compose.yml` и передай:

```bash
export HACKER_SOFT_TG_ALLOWED_IDS="123456789"
docker compose up --build bot
```

В фоне:

```bash
docker compose up --build -d bot
```

Docker-образ ставит backend-инструменты на этапе сборки.
Чтобы сборка была стабильнее, Dockerfile скачивает готовые Linux-релизы `subfinder`, `dnsx`, `httpx`, `naabu`, `katana`, `nuclei` и `amass`, а не компилирует их через Go toolchain.

Разовый пентест через Docker:

```bash
docker compose run --rm scan pentest example.com --out reports/example-pentest
```

Если Telegram API из контейнера дает SSL/network ошибки, а на хосте есть локальный HTTP proxy:

```bash
export HACKER_SOFT_TG_PROXY="http://host.docker.internal:7890"
docker compose up --build bot
```

Если Telegram открывается только через VPN, лучше не гонять через VPN сам сканер.
Используй HTTP-proxy только для Telegram API:

```bash
export HACKER_SOFT_TG_PROXY="http://127.0.0.1:7890"
python3 -m hacker_soft.bot
```

Так бот общается с Telegram через proxy, а проверки доменов идут обычным прямым соединением.
`socks5://` здесь не поддерживается без дополнительных зависимостей; нужен именно HTTP/HTTPS proxy.

Временный открытый режим:

```bash
python3 -m hacker_soft.bot --allow-anyone
```

Основной сценарий в Telegram:

```text
1. Нажать кнопку "Запустить анализ"
2. Отправить домен: example.com
3. Дождаться HTML-отчета с recon, безопасными проверками, endpoints, портами, документами и dorks
```

Бот всегда запускает полный стандартный сценарий: deep profile, safe active checks, backend-инструменты, nuclei, crawling и auto dork search.
Команда `/pentest example.com` делает то же самое явно.
В HTML-отчет встраиваются dork-команды, ссылки Google/Bing/DuckDuckGo,
автоматическая выдача поисковиков, найденные документы и артефакты модулей.

Служебная команда для проверки инструментов:

```text
/tools
```

Она не отображается кнопкой в боте; проще проверять из консоли через `python3 -m hacker_soft tools`.

Бот вернет адаптивный `report.html`, который удобно открывается с телефона и компьютера.

## Optional local tools

Движок использует эти инструменты, если они уже установлены:

- `dig` для DNS-записей
- `subfinder`, `dnsx`, `httpx`, `naabu`, `katana`, `nuclei` из ProjectDiscovery
- `amass` для passive attack-surface mapping
- `reconftw` или `reconftw.sh` для heavy workflow режима

Docker-образ ставит `subfinder`, `dnsx`, `httpx`, `naabu`, `katana`, `nuclei`
и `amass`. `reconFTW` в образ не входит; если включить `--heavy-tools` без
установленного `reconftw`, отчет покажет техническую ошибку `reconFTW не найден`.

## Ограничения

- `nuclei` запускается безопасно по шаблонам ProjectDiscovery, но на больших или
  медленных целях может упереться в timeout; в таком случае отчет сохраняет
  логи и помечает результат как технически неполный.
- `naabu` иногда дает шумный результат, когда сеть/цель отвечает одинаково на
  множество портов. Такие порты нужно перепроверять перед выводами.
- `exposure_paths` проверяет типовые чувствительные пути. Если приложение
  возвращает одинаковую login/error page с HTTP `200` на любые URL, возможны
  false positive, их надо смотреть вручную.
- Поисковики часто режут автоматические dork-запросы антиботом; найденные
  частичные результаты все равно попадают в отчет.
