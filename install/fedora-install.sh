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
REPO_URL="${1:-${SITECHAT_REPO_URL:-}}"
REPO_BRANCH="${SITECHAT_REPO_BRANCH:-main}"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script as root."
    exit 1
  fi
}

require_repo_url() {
  if [[ -z "${REPO_URL}" ]]; then
    echo "Usage: sudo bash install/fedora-install.sh <git-repo-url>"
    echo "Or set SITECHAT_REPO_URL in the environment."
    exit 1
  fi
}

log() {
  echo "[sitechat] $*"
}

install_packages() {
  log "Installing system packages"
  dnf install -y curl git

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

clone_or_update_repo() {
  if [[ -d "${APP_ROOT}/.git" ]]; then
    log "Existing git checkout found in ${APP_ROOT}, updating it"
    sudo -u "${APP_USER}" git -C "${APP_ROOT}" fetch --all --prune
    sudo -u "${APP_USER}" git -C "${APP_ROOT}" checkout "${REPO_BRANCH}"
    sudo -u "${APP_USER}" git -C "${APP_ROOT}" pull --ff-only origin "${REPO_BRANCH}"
    return
  fi

  if [[ -e "${APP_ROOT}" ]] && [[ -n "$(find "${APP_ROOT}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
    echo "${APP_ROOT} exists and is not an existing git checkout. Move it or remove it first."
    exit 1
  fi

  log "Cloning ${REPO_URL} into ${APP_ROOT}"
  rm -rf "${APP_ROOT}"
  install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "$(dirname "${APP_ROOT}")"
  sudo -u "${APP_USER}" git clone --branch "${REPO_BRANCH}" "${REPO_URL}" "${APP_ROOT}"
}

prepare_runtime_dirs() {
  log "Preparing runtime directories"
  install -d -m 0750 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_ROOT}/data"
  install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_ROOT}/engine/imagi"
}

fix_ownership_and_modes() {
  log "Fixing ownership and permissions"
  chown -R "${APP_USER}:${APP_GROUP}" "${APP_ROOT}"
  find "${APP_ROOT}" -type d -exec chmod 0755 {} \;
  find "${APP_ROOT}" -type f -exec chmod 0644 {} \;

  chmod 0755 "${APP_ROOT}/install/fedora-install.sh"
  chmod 0755 "${APP_ROOT}/server.js"
  chmod 0750 "${APP_ROOT}/data"
  chmod 0755 "${APP_ROOT}/engine/imagi"
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
  sudo -u ${APP_USER} git -C ${APP_ROOT} pull
  systemctl restart ${APP_NAME}.service
  journalctl -u ${APP_NAME}.service -f

The app is listening on ${APP_HOST}:${APP_PORT}.
EOF
}

main() {
  require_root
  require_repo_url
  install_packages
  create_user
  clone_or_update_repo
  prepare_runtime_dirs
  fix_ownership_and_modes
  write_env
  write_service
  enable_service
  post_install_notes
}

main "$@"
