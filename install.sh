#!/usr/bin/env bash
# GoServerPanel — скрипт автоустановки (Debian / Ubuntu).
#
#   curl -fsSL https://raw.githubusercontent.com/Karatells/GoServerPanel/main/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --with-nginx --with-php --with-mysql --allow-ip 203.0.113.5
#
# Порядок получения бинарника: локальная сборка (если запущено из репозитория) →
# готовый релиз с GitHub → сборка из исходников (при необходимости ставится Go).
set -Eeuo pipefail

REPO="Karatells/GoServerPanel"
BRANCH="main"
GO_VERSION="1.24.7"
BIN="/usr/local/bin/goserverpanel"
CONF_DIR="/etc/goserverpanel"
DATA_DIR="/var/lib/goserverpanel"
UNIT="/etc/systemd/system/goserverpanel.service"

PORT="8443"
ALLOW_IPS=()
WITH_NGINX=0; WITH_PHP=0; WITH_MYSQL=0; WITH_PG=0
FROM_SOURCE=0
UNINSTALL=0
PURGE=0

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_off=$'\e[0m'
info() { echo "${c_grn}==>${c_off} $*"; }
warn() { echo "${c_ylw}!!${c_off} $*" >&2; }
die()  { echo "${c_red}ОШИБКА:${c_off} $*" >&2; exit 1; }

usage() {
  cat <<EOF
Использование: install.sh [опции]

  --port N          порт панели (по умолчанию 8443)
  --allow-ip X      разрешить доступ только с IP/CIDR (можно указывать несколько раз)
  --with-nginx      установить nginx
  --with-php        установить PHP-FPM 8.3 (репозиторий ondrej/php на Ubuntu)
  --with-mysql      установить MariaDB
  --with-postgres   установить PostgreSQL
  --from-source     не скачивать релиз, а собирать из исходников
  --uninstall       удалить панель (данные сохраняются)
  --purge           вместе с --uninstall: удалить также конфиг и данные ($DATA_DIR)
  -h, --help        эта справка
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)          PORT="${2:?}"; shift 2 ;;
    --allow-ip)      ALLOW_IPS+=("${2:?}"); shift 2 ;;
    --with-nginx)    WITH_NGINX=1; shift ;;
    --with-php)      WITH_PHP=1; shift ;;
    --with-mysql)    WITH_MYSQL=1; shift ;;
    --with-postgres) WITH_PG=1; shift ;;
    --from-source)   FROM_SOURCE=1; shift ;;
    --uninstall)     UNINSTALL=1; shift ;;
    --purge)         PURGE=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) usage; die "неизвестная опция: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "запустите от root (sudo)."
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] || die "некорректный порт: $PORT"
for ip in "${ALLOW_IPS[@]}"; do
  [[ "$ip" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "некорректный IP/CIDR: $ip"
done

# ---------- удаление ----------
if [[ $UNINSTALL -eq 1 ]]; then
  info "Останавливаю и удаляю службу"
  systemctl disable --now goserverpanel 2>/dev/null || true
  rm -f "$UNIT" "$BIN"
  systemctl daemon-reload 2>/dev/null || true
  if [[ $PURGE -eq 1 ]]; then
    rm -rf "$CONF_DIR" "$DATA_DIR"
    info "Конфиг и данные удалены"
  else
    info "Конфиг ($CONF_DIR) и данные ($DATA_DIR) сохранены; для удаления добавьте --purge"
  fi
  info "Nginx-конфиги сайтов (gsp-*.conf) и сайты в /var/www не затрагивались"
  exit 0
fi

# ---------- проверки окружения ----------
[[ "$(uname -s)" == "Linux" ]] || die "поддерживается только Linux."
command -v systemctl >/dev/null || die "нужен systemd."
command -v apt-get   >/dev/null || die "скрипт рассчитан на Debian/Ubuntu (apt)."

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "неподдерживаемая архитектура: $(uname -m)" ;;
esac

export DEBIAN_FRONTEND=noninteractive
APT_UPDATED=0
apt_install() {
  if [[ $APT_UPDATED -eq 0 ]]; then apt-get update -qq; APT_UPDATED=1; fi
  apt-get install -y -qq "$@"
}

info "Устанавливаю базовые пакеты"
apt_install ca-certificates curl tar >/dev/null

# ---------- получение бинарника ----------
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
NEWBIN="$TMP/goserverpanel"

ensure_go() {
  if command -v go >/dev/null; then
    local have; have="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
    if [[ "$(printf '%s\n%s\n' "1.24" "$have" | sort -V | head -1)" == "1.24" ]]; then return; fi
  fi
  info "Устанавливаю Go $GO_VERSION (для сборки)"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o "$TMP/go.tgz"
  mkdir -p "$TMP/goroot" && tar -C "$TMP/goroot" -xzf "$TMP/go.tgz"
  export PATH="$TMP/goroot/go/bin:$PATH"
  export GOCACHE="$TMP/gocache" GOPATH="$TMP/gopath"
}

build_from() {  # $1 — каталог с исходниками
  ensure_go
  info "Собираю из исходников"
  (cd "$1" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$NEWBIN" ./cmd/panel)
}

SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/cmd/panel/main.go" ]]; then
  info "Найден локальный репозиторий: $SCRIPT_DIR"
  build_from "$SCRIPT_DIR"
else
  got=0
  if [[ $FROM_SOURCE -eq 0 ]]; then
    url="https://github.com/${REPO}/releases/latest/download/goserverpanel-linux-${ARCH}"
    info "Скачиваю релиз: $url"
    if curl -fsSL "$url" -o "$NEWBIN" 2>/dev/null; then
      if curl -fsSL "${url}.sha256" -o "$TMP/sum" 2>/dev/null; then
        (cd "$TMP" && echo "$(cut -d' ' -f1 sum)  goserverpanel" | sha256sum -c - >/dev/null) \
          || die "контрольная сумма релиза не совпала"
        info "Контрольная сумма проверена"
      else
        warn "файл контрольной суммы недоступен — пропускаю проверку"
      fi
      got=1
    else
      warn "готовый релиз недоступен — перехожу к сборке из исходников"
    fi
  fi
  if [[ $got -eq 0 ]]; then
    apt_install git >/dev/null
    info "Клонирую https://github.com/${REPO} (ветка $BRANCH)"
    git clone --depth 1 --branch "$BRANCH" "https://github.com/${REPO}.git" "$TMP/src" >/dev/null 2>&1 \
      || die "не удалось клонировать репозиторий"
    build_from "$TMP/src"
  fi
fi

chmod 0755 "$NEWBIN"
"$NEWBIN" -version >/dev/null || die "собранный бинарник не запускается"

# ---------- зависимости ----------
if [[ $WITH_NGINX -eq 1 ]]; then
  info "Устанавливаю nginx"
  apt_install nginx >/dev/null
  systemctl enable --now nginx >/dev/null 2>&1 || true
fi
if [[ $WITH_MYSQL -eq 1 ]]; then
  info "Устанавливаю MariaDB"
  apt_install mariadb-server mariadb-client >/dev/null
  systemctl enable --now mariadb >/dev/null 2>&1 || true
fi
if [[ $WITH_PG -eq 1 ]]; then
  info "Устанавливаю PostgreSQL"
  apt_install postgresql postgresql-client >/dev/null
  systemctl enable --now postgresql >/dev/null 2>&1 || true
fi
if [[ $WITH_PHP -eq 1 ]]; then
  info "Устанавливаю PHP-FPM 8.3"
  if . /etc/os-release && [[ "${ID:-}" == "ubuntu" ]]; then
    apt_install software-properties-common >/dev/null
    add-apt-repository -y ppa:ondrej/php >/dev/null 2>&1 || warn "не удалось подключить ppa:ondrej/php"
    apt-get update -qq
  fi
  apt_install php8.3-fpm php8.3-cli php8.3-mysql php8.3-curl php8.3-xml php8.3-mbstring php8.3-zip php8.3-gd >/dev/null \
    || warn "не удалось установить PHP 8.3 — установите нужную версию позже в разделе «PHP & Модули»"
fi

# ---------- установка ----------
info "Устанавливаю панель"
WAS_ACTIVE=0
systemctl is-active --quiet goserverpanel 2>/dev/null && WAS_ACTIVE=1
[[ $WAS_ACTIVE -eq 1 ]] && systemctl stop goserverpanel
install -m 0755 "$NEWBIN" "$BIN"
install -d -m 0700 "$CONF_DIR" "$DATA_DIR"

if [[ -f "$CONF_DIR/config.yaml" ]]; then
  info "Конфиг $CONF_DIR/config.yaml уже существует — оставляю без изменений"
else
  {
    echo "# GoServerPanel — сгенерировано install.sh"
    echo "listen: 0.0.0.0:${PORT}"
    echo "data_dir: ${DATA_DIR}"
    if [[ ${#ALLOW_IPS[@]} -gt 0 ]]; then
      echo "allow_cidrs:"
      for ip in "${ALLOW_IPS[@]}"; do echo "  - ${ip}"; done
    else
      echo "allow_cidrs: []"
    fi
    cat <<'YAML'
session_hours: 12
terminal_enabled: true
shell: /bin/bash
nginx_sites_available: /etc/nginx/sites-available
nginx_sites_enabled: /etc/nginx/sites-enabled
nginx_bin: nginx
nginx_log_dir: /var/log/nginx
www_root: /var/www
web_user: www-data
php_etc_dir: /etc/php
php_socket_dir: /run/php
files_roots:
  - /var/www
  - /etc/nginx
dry_run: false
YAML
  } > "$CONF_DIR/config.yaml"
  chmod 0600 "$CONF_DIR/config.yaml"
fi

cat > "$UNIT" <<EOF
[Unit]
Description=GoServerPanel
After=network-online.target nginx.service
Wants=network-online.target

[Service]
ExecStart=$BIN -config $CONF_DIR/config.yaml
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"

systemctl daemon-reload
systemctl enable --now goserverpanel >/dev/null 2>&1
sleep 2
systemctl is-active --quiet goserverpanel || { journalctl -u goserverpanel -n 30 --no-pager || true; die "служба не запустилась"; }

# ---------- итог ----------
LISTEN_PORT="$(grep -E '^listen:' "$CONF_DIR/config.yaml" | head -1 | sed -E 's/.*:([0-9]+)\s*$/\1/')"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
PASS_FILE="$DATA_DIR/initial_admin_password"
for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -f "$PASS_FILE" ]] && break; sleep 1; done

echo
echo "${c_grn}============================================================${c_off}"
echo " GoServerPanel установлен"
echo " Адрес:   https://${IP:-<IP-сервера>}:${LISTEN_PORT:-$PORT}   (сертификат самоподписанный)"
if [[ -f "$PASS_FILE" ]]; then
  echo " Логин:   admin"
  echo " Пароль:  $(cat "$PASS_FILE")"
  echo "          (файл $PASS_FILE — удалите после входа и смены пароля)"
else
  echo " Администратор уже создан ранее. Сброс пароля:"
  echo "   $BIN -config $CONF_DIR/config.yaml -reset-password admin"
fi
echo "${c_grn}============================================================${c_off}"
if [[ ${#ALLOW_IPS[@]} -eq 0 ]]; then
  warn "Доступ к панели не ограничен по IP. Рекомендуется задать allow_cidrs в $CONF_DIR/config.yaml и включить 2FA."
fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  warn "Включён ufw — откройте порт панели: ufw allow ${LISTEN_PORT:-$PORT}/tcp"
fi
echo "Управление: systemctl status|restart goserverpanel · журнал: journalctl -u goserverpanel -f"
