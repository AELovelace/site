#!/usr/bin/env bash
set -euo pipefail

APP_NAME="sitechat"
APP_USER="sitechat"
APP_GROUP="sitechat"
APP_ROOT="/opt/sitechat"
APP_PORT="3000"
APP_HOST="0.0.0.0"
NODE_MAJOR="22"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
ENV_FILE="/etc/${APP_NAME}.env"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_REPO_SOURCE="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

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
  dnf install -y curl git rsync

  if ! command -v node >/dev/null 2>&1; then
    log "Installing Node.js ${NODE_MAJOR}.x"
    curl -fsSL "https://rpm.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
    dnf install -y nodejs
  fi
}

create_user() {
  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    log "Creating service user ${APP_USER}"
    useradd --system --create-home --home-dir "${APP_ROOT}" --shell /bin/bash "${APP_USER}"
  fi
}

copy_repo() {
  log "Copying repository into ${APP_ROOT}"
  install -d -m 0755 -o root -g root "${APP_ROOT}"
  rsync -a --delete --exclude "data/" "${APP_REPO_SOURCE}/" "${APP_ROOT}/"
  install -d -m 0750 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_ROOT}/data"
  chown -R "${APP_USER}:${APP_GROUP}" "${APP_ROOT}"
  chmod 0755 "${APP_ROOT}"
  chmod 0750 "${APP_ROOT}/data"
  chmod 0755 "${APP_ROOT}/install/fedora-install.sh"
}

write_env() {
  log "Writing environment file ${ENV_FILE}"
  cat > "${ENV_FILE}" <<EOF
PORT=${APP_PORT}
HOST=${APP_HOST}
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
}

post_install_notes() {
  cat <<EOF

Install complete.

Repo/app path:
  ${APP_ROOT}

Update flow:
  sudo -u ${APP_USER} git -C ${APP_ROOT} pull
  sudo systemctl restart ${APP_NAME}.service

Logs:
  journalctl -u ${APP_NAME}.service -f
EOF
}

main() {
  require_root
  install_packages
  create_user
  copy_repo
  write_env
  write_service
  enable_service
  post_install_notes
}

main "$@"
