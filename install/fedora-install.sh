#!/usr/bin/env bash
set -euo pipefail

APP_NAME="sitechat"
APP_USER="sitechat"
APP_GROUP="sitechat"
APP_ROOT="/opt/sitechat"
APP_PORT="3000"
APP_REPO_SOURCE="${PWD}"
NODE_MAJOR="22"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
ENV_FILE="/etc/${APP_NAME}.env"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script as root."
    exit 1
  fi
}

log() {
  echo "[sitechat] $*"
}

install_packages() {
  log "Installing system packages"
  dnf install -y curl rsync

  if ! command -v node >/dev/null 2>&1; then
    log "Installing Node.js ${NODE_MAJOR}.x"
    curl -fsSL "https://rpm.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
    dnf install -y nodejs
  fi
}

create_user() {
  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    log "Creating service user ${APP_USER}"
    useradd --system --home-dir "${APP_ROOT}" --shell /sbin/nologin "${APP_USER}"
  fi
}

create_layout() {
  log "Creating application directories"
  install -d -m 0755 -o root -g root "${APP_ROOT}"
  install -d -m 0750 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_ROOT}/data"
  install -d -m 0755 -o root -g root "${APP_ROOT}/engine"
  install -d -m 0755 -o root -g root "${APP_ROOT}/install"
}

sync_app() {
  log "Copying application files into ${APP_ROOT}"
  rsync -a --delete \
    --exclude ".git" \
    --exclude "data/*.db" \
    --exclude "data/*.sqlite*" \
    "${APP_REPO_SOURCE}/server.js" \
    "${APP_REPO_SOURCE}/package.json" \
    "${APP_REPO_SOURCE}/engine/" \
    "${APP_REPO_SOURCE}/install/" \
    "${APP_ROOT}/"

  chown -R root:root "${APP_ROOT}"
  chown -R "${APP_USER}:${APP_GROUP}" "${APP_ROOT}/data"
}

write_env() {
  log "Writing environment file ${ENV_FILE}"
  cat > "${ENV_FILE}" <<EOF
PORT=${APP_PORT}
NODE_ENV=production
EOF
  chmod 0640 "${ENV_FILE}"
  chown root:"${APP_GROUP}" "${ENV_FILE}"
}

write_service() {
  log "Writing systemd unit ${SERVICE_FILE}"
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=sitechat Node.js chat service
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_ROOT}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/node ${APP_ROOT}/server.js
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${APP_ROOT}/data ${APP_ROOT}/engine/imagi

[Install]
WantedBy=multi-user.target
EOF
}

enable_service() {
  log "Reloading systemd and enabling service"
  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}.service"
  systemctl --no-pager --full status "${APP_NAME}.service" || true
}

post_install_notes() {
  cat <<EOF

Install complete.

Important paths:
  App root: ${APP_ROOT}
  Service:  ${APP_NAME}.service
  Env file: ${ENV_FILE}

Useful commands:
  journalctl -u ${APP_NAME}.service -f
  systemctl restart ${APP_NAME}.service
  systemctl status ${APP_NAME}.service

The app is listening on port ${APP_PORT}. Put nginx in front of it on the webserver.
EOF
}

main() {
  require_root
  install_packages
  create_user
  create_layout
  sync_app
  write_env
  write_service
  enable_service
  post_install_notes
}

main "$@"
