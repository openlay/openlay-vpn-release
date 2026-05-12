#!/bin/bash
# =============================================================================
# OpenLay VPN Management Server + App API — Update Script
# Run as root: ./update.sh
#
# Stops services, copies new files, reinstalls deps, restarts services.
# Preserves .env files and TLS certificates.
# =============================================================================
set -e

SERVICE_USER="olv-management"
HOME_DIR="/home/${SERVICE_USER}"
MGMT_DIR="${HOME_DIR}/wireguard-management"
APP_API_DIR="${HOME_DIR}/app-api"
MGMT_SERVICE="olv-management"
APP_API_SERVICE="olv-app-api"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then error "This script must be run as root"; fi

# Verify existing installation
if [ ! -d "$MGMT_DIR" ]; then
  error "No existing installation found at ${MGMT_DIR}. Run install.sh first."
fi

info "=== OpenLay VPN Management — Update ==="
echo ""

# ---------------------------------------------------------------------------
# 1. Stop services
# ---------------------------------------------------------------------------
info "[1/5] Stopping services..."
systemctl stop "$APP_API_SERVICE" 2>/dev/null || true
systemctl stop "$MGMT_SERVICE" 2>/dev/null || true
info "  Services stopped"

# ---------------------------------------------------------------------------
# 2. Backup current installation
# ---------------------------------------------------------------------------
info "[2/5] Backing up..."
BACKUP_DIR="${HOME_DIR}/backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r "$MGMT_DIR/server/src" "$BACKUP_DIR/server-src" 2>/dev/null || true
cp -r "$APP_API_DIR/src" "$BACKUP_DIR/app-api-src" 2>/dev/null || true
info "  Backup: ${BACKUP_DIR}"

# ---------------------------------------------------------------------------
# 3. Copy new files (preserve .env, certs)
# ---------------------------------------------------------------------------
info "[3/5] Updating application files..."

# Management server
rm -rf "$MGMT_DIR/server/src"
cp -r "$SCRIPT_DIR/server/src" "$MGMT_DIR/server/src"
cp "$SCRIPT_DIR/server/package.json" "$MGMT_DIR/server/" 2>/dev/null || true
cp "$SCRIPT_DIR/server/package-lock.json" "$MGMT_DIR/server/" 2>/dev/null || true

# Drop any prior install's admin UI tree — retired 2026-05-12.
rm -rf "$MGMT_DIR/client"

# App API
rm -rf "$APP_API_DIR/src"
cp -r "$SCRIPT_DIR/app-api/src" "$APP_API_DIR/src"
cp "$SCRIPT_DIR/app-api/package.json" "$APP_API_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/app-api/package-lock.json" "$APP_API_DIR/" 2>/dev/null || true

chown -R "$SERVICE_USER:$SERVICE_USER" "$HOME_DIR"
info "  Files updated"

# ---------------------------------------------------------------------------
# 4. Reinstall dependencies
# ---------------------------------------------------------------------------
info "[4/5] Installing dependencies..."

cd "$MGMT_DIR/server"
sudo -u "$SERVICE_USER" npm install --omit=dev 2>&1 | tail -1
info "  Management server deps installed"

cd "$APP_API_DIR"
sudo -u "$SERVICE_USER" npm install --omit=dev 2>&1 | tail -1
info "  App API deps installed"

# ---------------------------------------------------------------------------
# 5. Restart services
# ---------------------------------------------------------------------------
info "[5/5] Restarting services..."

systemctl daemon-reload
systemctl restart "$MGMT_SERVICE"
sleep 3
systemctl restart "$APP_API_SERVICE"
sleep 3

MGMT_OK=false; API_OK=false
systemctl is-active --quiet "$MGMT_SERVICE" && MGMT_OK=true
systemctl is-active --quiet "$APP_API_SERVICE" && API_OK=true

echo ""
echo "==========================================="
if [ "$MGMT_OK" = true ] && [ "$API_OK" = true ]; then
  echo -e "${GREEN}Update complete! Both services running.${NC}"
else
  echo -e "${YELLOW}Update complete with warnings:${NC}"
  [ "$MGMT_OK" = false ] && warn "  Management: NOT running (journalctl -u ${MGMT_SERVICE} -n 20)"
  [ "$API_OK" = false ] && warn "  App API: NOT running (journalctl -u ${APP_API_SERVICE} -n 20)"
  echo ""
  echo "  Rollback: cp -r ${BACKUP_DIR}/* back to original locations"
fi
echo "==========================================="
echo ""
