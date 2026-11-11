# GoServerPanel

Легковесная панель управления веб-сервером на Go: один статический бинарник (~8 МБ), без внешних Go-зависимостей, интерфейс встроен через `go:embed`.

## Быстрый старт (Debian/Ubuntu)

Автоустановка одной командой (от root):

```bash
curl -fsSL https://raw.githubusercontent.com/Karatells/GoServerPanel/main/install.sh | sudo bash
```

С дополнительными компонентами и ограничением доступа:

```bash
curl -fsSL https://raw.githubusercontent.com/Karatells/GoServerPanel/main/install.sh | \
  sudo bash -s -- --with-nginx --with-php --with-mysql --allow-ip 203.0.113.5 --port 8443
```

Опции: `--port N`, `--allow-ip IP/CIDR` (можно несколько), `--with-nginx`, `--with-php`, `--with-mysql`, `--with-postgres`, `--from-source`, `--uninstall [--purge]`.
Скрипт берёт бинарник из GitHub Releases (с проверкой SHA-256), а если релиза нет — клонирует репозиторий и собирает из исходников (при необходимости ставит Go). Повторный запуск обновляет панель, не трогая конфиг и данные. Релиз публикуется командой `git tag v0.1.0 && git push --tags` (workflow `release.yml`).

Из клонированного репозитория: `sudo ./install.sh` (или `make install`). Пароль администратора скрипт выводит в конце (он же в `/var/lib/goserverpanel/initial_admin_password`).

Панель: `https://<сервер>:8443` (при первом запуске создаётся самоподписанный сертификат).
Сброс пароля: `goserverpanel -config /etc/goserverpanel/config.yaml -reset-password admin`.

Для проверки без изменения системы: `dry_run: true` в конфиге — изменяющие команды (apt, systemctl, nginx, СУБД) не выполняются.

## Что реализовано

| Модуль | Состояние |
|---|---|
| Ядро: роутер, JWT-сессии (cookie, HttpOnly, SameSite=Strict), PBKDF2-SHA256, TOTP 2FA, роли admin/viewer, аудит, ограничение по IP/CIDR, защита от перебора | ✅ |
| Nginx: генерация vhost, алиасы, редиректы, кэш статики, ручной редактор конфига, `nginx -t` перед применением с откатом, логи сайтов | ✅ |
| Reverse proxy: правила по путям, WebSocket, заголовки, балансировка (round-robin / least_conn / ip_hash) | ✅ |
| PHP: обнаружение версий 7.4–8.4, установка php-fpm (apt, ondrej/php), модули (установка/удаление/вкл/выкл), `php.ini`-директивы с перезапуском пула | ✅ |
| БД: MySQL/MariaDB и PostgreSQL — базы, пользователи, права, бэкап/восстановление (gzip) | ✅ |
| Автоустановка CMS: WordPress (конфиг создаётся автоматически), Joomla, Drupal, OpenCart, Laravel (через composer) | ✅ |
| PKI: несколько корневых CA — создание (RSA-4096) или **загрузка своего** (сертификат + ключ PEM; RSA/ECDSA/Ed25519), выпуск через CSR с выбором CA, SAN (DNS/IP), отзыв, CRL для каждого CA, привязка к сайту → HTTPS. CA старых версий переносится автоматически | ✅ |
| Веб-терминал: PTY через WebSocket, повторное подтверждение пароля/2FA, одноразовый токен, аудит | ✅ |
| Файловый менеджер: ограничен `files_roots`, защита от `..` и симлинков | ✅ |
| Дашборд: CPU/RAM/диски в реальном времени (WebSocket), службы systemd | ✅ |

## Отличия от концепт-документа

Сборка велась без доступа к сети, поэтому использована только стандартная библиотека Go:

- **SQLite → JSON-файл** (`panel.json`, атомарная запись, 0600). Хватает для данных панели; переход на SQLite — отдельный пакет `internal/store`.
- **bcrypt → PBKDF2-SHA256** (310 000 итераций, `crypto/pbkdf2`).
- **Casbin → простые роли** `admin` / `viewer`.
- **Fiber/Chi → `net/http`** (ServeMux Go 1.22+); **WebSocket** и **PTY** написаны на stdlib/syscall.
- **Tailwind/Alpine/Vite → чистые HTML/CSS/JS** без сборки.
- **xterm.js**: встроен простой эмулятор терминала (цвета, редактирование строки; vim/htop отображаются неточно). Для полноценного терминала положите `xterm.js`, `xterm.css` (и опционально `xterm-addon-fit.js`) в `ui/static/vendor/` и пересоберите — панель подхватит их автоматически.
- **config.yaml** — плоское подмножество YAML (скаляры и списки).

## Безопасность

- Панель работает от root — это требуется для управления службами; **обязательно** ограничьте доступ `allow_cidrs`, включите 2FA.
- Все значения, попадающие в конфиги nginx/SQL/команды, валидируются по белым спискам; команды запускаются без shell.
- Терминал и файловый менеджер доступны только `admin`; терминал требует повторного ввода пароля.
- Закрытый ключ импортированного CA хранится на сервере (`data_dir/pki/cas/<id>/ca.key`, права 0600): панель подписывает им сертификаты. Импортируйте только CA, предназначенные для такого использования (например, отдельный промежуточный CA), а не корпоративный корень.
- Ручной конфиг nginx (`raw_config`) может содержать любые директивы — доступен только `admin`, применяется лишь после `nginx -t`.

## Известные ограничения / что проверить на боевом сервере

Автотесты и e2e в браузере прошли в `dry_run`; реальные вызовы `apt`, `systemctl`, `mysql`, `psql`, `composer` и скачивание CMS в среде разработки **не выполнялись**.

- URL-адреса Joomla и OpenCart закреплены на конкретных версиях (`internal/installer/installer.go`) — проверьте актуальность. WordPress и Drupal используют «latest»-ссылки.
- Joomla/Drupal/OpenCart: файлы, БД и vhost создаются автоматически, а данные БД выдаются в логе для мастера установки CMS (автогенерация их конфигов не реализована).
- PrestaShop из концепта не включён (архив содержит вложенный zip).
- Для MySQL предполагается вход root по unix-сокету (по умолчанию на Debian/Ubuntu).

## Структура

```
cmd/panel/        точка входа
internal/         auth config databases execx files installer jobs nginx php pki store system terminal web ws
ui/static/        фронтенд (embed)
deploy/           systemd-юнит
```

Тесты: `make test`.
