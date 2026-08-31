# Dragon Forge X — гайд по софту

## Структура логов
## Модули

| Модуль | Назначение |
|---|---|
| recon | Smart fingerprinting: RDAP, DNS, CMS/Frameworks, Favicon hash, WAF |
| portscan | встроенный TCP-сканер портов + Banner Grabbing (без nmap) |
| scan | TLS, directory brute, внешние инструменты |
| app | краулер, парсер HTML-форм, security headers, sensitive data, JS/JSON routes |
| js | добыча endpoint'ов из HTML/JS, source maps, секреты |
| dom | поиск DOM XSS sinks |
| param | fuzz GET-параметров |
| secret | поиск .env, .git, backup, db-файлов |
| file | /videos, /api/stream, /api/downloads, traversal |
| cors | глубокие CORS-проверки (prefix, suffix, subdomain, backtick, creds) |
| header | header bypass, X-Original-URL, X-User и т.д. |
| rate | rate limit разведка |
| idor | проверка чужих объектов |
| xss | stored/reflected XSS лаборатория (URL + HTML формы) |
| csrf | генерация CSRF PoC для обнаруженных форм |
| sqli | SQL/NoSQL базовые проверки + фаззинг форм |
| cache | cache poisoning разведка |
| ssrf | SSRF проверки через прокси-эндпоинты |
| cloud | Cloud metadata SSRF проверки |
| openapi | парсинг OpenAPI/Swagger + тестирование эндпоинтов |
| jwt | JWT анализ (weak secret, alg:none, jku, jwk, kid traversal/sqli, RS->HS) |
| subdomain | пассивный сбор поддоменов через CT-логи (crt.sh) и проверка liveness |
| subtakeover | поиск брошенных поддоменов (S3, GitHub, Heroku, Azure, etc.) |
| csp | детальный анализ Content-Security-Policy |
| wasm | поиск Service Worker и WASM модулей |
| oauth | проверка OAuth конфигураций и redirect_uri |
| deser | детекция сериализованных объектов (PHP, Java, .NET) |
| ssti | детекция Server-Side Template Injection (Jinja2, Twig, Freemarker, ERB, Pug) |
| rce | аудит OS Command Injection (Echo-reflection + Time-based) |
| xxe | проверка обработки XML External Entity (XXE) |
| mass | проверка Mass Assignment уязвимостей |
| proto | Prototype Pollution проверки |
| smuggling | Raw Socket HTTP Request Smuggling (CL.TE / TE.CL) |
| external | nmap/другие тулзы, если установлены |
| dedup | группировка и дедупликация находок |
| diff | сравнение с предыдущими сканированиями |

## Флаги

```bash
-u                 цель (URL)
--all              все модули
--modules          список модулей через запятую
--active           активные/mutating проверки
-H                 кастомные HTTP-заголовки (повторяемый: -H "Auth: Bearer ...")
--threads          количество параллельных потоков (по умолчанию 10)
--delay            задержка между запросами в секундах
--external         запуск внешних тулзов (nmap, nuclei)
--out              корень вывода, по умолчанию .
--result-dir       имя папки результата, по умолчанию result
--max-pages        максимум страниц для краулера
--timeout          HTTP timeout в секундах
--insecure         не проверять TLS
--username         логин для basic auth
--password         пароль для basic auth
--diff             папка предыдущего скана для сравнения
```

## Отчёты

- **`report.html`** — современный интерактивный Dashboard с фильтрацией по уровню критичности, поиском, сводкой технологий и готовыми PoC curl-командами.
- **`report.json`** — структурированный JSON со всеми находками.
- **`report.sarif`** — стандарт SARIF v2.1.0 для интеграции с GitHub Code Scanning и IDE.
- **`full_output.txt`** — единый текстовый дамп всех логов.

## Примеры

Пассивный базовый прогон:

```bash
./dragon-forge-x -u https://example.com
```

Все модули без опасных изменений:

```bash
./dragon-forge-x -u https://example.com --all
```

Все модули + активные проверки:

```bash
./dragon-forge-x -u https://example.com --all --active
```

Только конкретные лаборатории:

```bash
./dragon-forge-x -u https://example.com --modules idor,xss,csrf,file --active
```

## Важно

- `--active` может создавать аккаунты, коллекции, запросы на изменение данных.
- `--external` может запускать nmap, если он установлен.
- Все логи пишутся в `<domain>/result/logs`.
