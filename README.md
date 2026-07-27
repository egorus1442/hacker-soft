# hacker-soft

Модульный defensive-сканер для внешней поверхности активов, которыми ты владеешь.
Есть CLI и Telegram-бот. Отчеты генерируются в `HTML`, `JSON` и `Markdown`.
HTML-отчет содержит пояснения простым языком: что найдено, чем это грозит и что делать.

Сканер намеренно не делает разрушительные вещи:

- без брутфорса
- без обхода авторизации
- без запуска эксплойтов
- без разрушительных payload'ов

Он собирает пассивный OSINT, поддомены, DNS/email security, HTTP/TLS-сигналы,
Google/Bing dorks, экспонированные пути, common ports и результаты optional CLI-инструментов.

## CLI

```bash
python3 -m hacker_soft scan example.com --out reports/example
```

Проверить, какие внешние инструменты уже установлены:

```bash
python3 -m hacker_soft tools
```

Fast passive-ish run:

```bash
python3 -m hacker_soft scan example.com --profile fast --out reports/example-fast
```

Include optional active checks:

```bash
python3 -m hacker_soft scan example.com --profile standard --active --with-tools --out reports/example-active
```

Автоматизированный defensive-пентест по своему домену: recon, безопасные проверки уязвимостей, nuclei, crawling и dorking:

```bash
python3 -m hacker_soft pentest example.com --out reports/example-pentest
```

Use optional tools when installed:

```bash
python3 -m hacker_soft scan example.com --profile deep --active --with-tools --out reports/example-tools
```

Автоматически собрать и распарсить выдачу Bing/DuckDuckGo по dorks:

```bash
python3 -m hacker_soft scan example.com --profile deep --auto-dork-search --max-dork-queries 50 --out reports/example-dorks
```

Тяжелые workflow-инструменты, например reconFTW:

```bash
python3 -m hacker_soft scan example.com --profile deep --active --with-tools --heavy-tools --out reports/example-heavy
```

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
3. Дождаться HTML-отчета с recon, проверками уязвимостей, endpoints, портами и Google Dorking
```

Бот всегда запускает полный стандартный сценарий: deep profile, safe active checks, backend-инструменты, nuclei, crawling и auto dork search.
Команда `/pentest example.com` делает то же самое явно.
В HTML-отчет встраиваются Google Dorking-команды, ссылки Google/Bing/DuckDuckGo, автоматическая выдача поисковиков и артефакты модулей.

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

API-ключи опциональны:

- `SHODAN_API_KEY`
- `CENSYS_API_ID`
- `CENSYS_API_SECRET`
- `GITHUB_TOKEN`

MVP не требует платных API.
