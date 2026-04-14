#!/bin/bash
# =============================================================================
# OpenLay VPN Management Server + App API — Uninstall Script
# Run as root: ./uninstall.sh [options]
#
# Usage:
#   ./uninstall.sh              # Interactive
#   ./uninstall.sh --force      # Remove everything without asking
#   ./uninstall.sh --keep-db    # Keep database
#   ./uninstall.sh --keep-user  # Keep user account
# =============================================================================
set -e

FORCE=false
KEEP_DB=false
KEEP_USER=false

for arg in "$@"; do
  case "$arg" in
    --force)     FORCE=true ;;
    --keep-db)   KEEP_DB=true ;;
    --keep-user) KEEP_USER=true ;;
    -h|--help)
      echo "Usage: ./uninstall.sh [--force] [--keep-db] [--keep-user]"
      exit 0
      ;;
  esac
done

SERVICE_USER="olv-management"
HOME_DIR="/home/${SERVICE_USER}"
MGMT_SERVICE="olv-management"
APP_API_SERVICE="olv-app-api"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

confirm() {
  if [ "$FORCE" = true ]; then return 0; fi
  read -p "  $1 [y/N] " -n 1 -r; echo
  [[ $REPLY =~ ^[Yy]$ ]]
}

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root"; exit 1
fi

echo -e "${RED}=== OpenLay VPN Management — Uninstaller ===${NC}"
echo ""

# 1. Stop services
info "[1/5] Stopping services..."
systemctl stop "$MGMT_SERVICE" 2>/dev/null || true
systemctl stop "$APP_API_SERVICE" 2>/dev/null || true
systemctl disable "$MGMT_SERVICE" 2>/dev/null || true
systemctl disable "$APP_API_SERVICE" 2>/dev/null || true
rm -f "/etc/systemd/system/${MGMT_SERVICE}.service"
rm -f "/etc/systemd/system/${APP_API_SERVICE}.service"
systemctl daemon-reload
info "  Services removed"

# 2. Remove application
info "[2/5] Removing application..."
if [ -d "$HOME_DIR" ]; then
  if confirm "Delete ${HOME_DIR}?"; then
    rm -rf "$HOME_DIR"
    info "  Application removed"
  fi
fi

# 3. Remove user
if [ "$KEEP_USER" != true ]; then
  info "[3/5] Removing user..."
  if id "$SERVICE_USER" &>/dev/null; then
    if confirm "Delete user '${SERVICE_USER}'?"; then
      userdel -r "$SERVICE_USER" 2>/dev/null || { userdel "$SERVICE_USER" 2>/dev/null; rm -rf "$HOME_DIR"; }
      info "  User removed"
    fi
  fi
else
  info "[3/5] Keeping user (--keep-user)"
fi

# 4. Database
if [ "$KEEP_DB" != true ]; then
  info "[4/5] Database..."
  warn "  Database NOT dropped automatically. To drop manually:"
  warn "  psql -U postgres -c 'DROP DATABASE wireguard_management;'"
else
  info "[4/5] Keeping database (--keep-db)"
fi

# 5. Firewall
info "[5/5] Reverting firewall..."
set +e
if command -v firewall-cmd &>/dev/null; then
  firewall-cmd --permanent --remove-port=3084/tcp 2>/dev/null || true
  firewall-cmd --permanent --remove-port=443/tcp 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null
elif command -v ufw &>/dev/null; then
  ufw delete allow 3084/tcp 2>/dev/null || true
  ufw delete allow 443/tcp 2>/dev/null || true
elif command -v iptables &>/dev/null; then
  iptables -D INPUT -p tcp --dport 3084 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
fi
set -e

echo ""
echo -e "${GREEN}Uninstall complete!${NC}"
echo ""
