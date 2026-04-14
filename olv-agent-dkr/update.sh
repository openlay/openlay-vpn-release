#!/bin/bash
# =============================================================================
# OpenLay VPN Agent (Docker) — Update Script
# Run as root: ./update.sh
# =============================================================================
set -e

INSTALL_DIR="/opt/olv-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then error "This script must be run as root"; fi
if [ ! -d "$INSTALL_DIR" ]; then error "No installation found at ${INSTALL_DIR}. Run install.sh first."; fi

info "=== OpenLay VPN Agent — Update ==="

info "[1/3] Stopping agent..."
cd "$INSTALL_DIR"
docker compose down 2>/dev/null || true

info "[2/3] Updating files..."
cp "$SCRIPT_DIR/Dockerfile" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/docker-compose.yml" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/docker-entrypoint.sh" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/package.json" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/package-lock.json" "$INSTALL_DIR/" 2>/dev/null || true
rm -rf "$INSTALL_DIR/src"
cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/docker-entrypoint.sh"
info "  Files updated (preserving .env)"

info "[3/3] Rebuilding and starting..."
docker compose build 2>&1 | tail -3
docker compose up -d 2>&1

cd "$OLDPWD"

echo ""
echo -e "${GREEN}Update complete!${NC}"
echo "  Logs: cd ${INSTALL_DIR} && docker compose logs -f"
echo ""
