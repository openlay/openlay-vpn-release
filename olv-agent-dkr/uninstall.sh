#!/bin/bash
# =============================================================================
# OpenLay VPN Agent (Docker) — Uninstall Script
# Run as root: ./uninstall.sh [--force] [--keep-data]
# =============================================================================
set -e

INSTALL_DIR="/opt/olv-agent"
FORCE=false
KEEP_DATA=false

for arg in "$@"; do
  case "$arg" in
    --force)     FORCE=true ;;
    --keep-data) KEEP_DATA=true ;;
    -h|--help)   echo "Usage: ./uninstall.sh [--force] [--keep-data]"; exit 0 ;;
  esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

confirm() {
  if [ "$FORCE" = true ]; then return 0; fi
  read -rp "  $1 [y/N] " -n 1 -r < /dev/tty; echo
  [[ $REPLY =~ ^[Yy]$ ]]
}

if [ "$EUID" -ne 0 ]; then echo "Run as root"; exit 1; fi

echo -e "${RED}=== OpenLay VPN Agent — Uninstaller ===${NC}"
echo ""

info "[1/3] Stopping containers..."
if [ -d "$INSTALL_DIR" ]; then
  cd "$INSTALL_DIR"
  docker compose down 2>/dev/null || true
  cd /
fi

if [ "$KEEP_DATA" != true ]; then
  info "[2/3] Removing Docker volumes..."
  docker volume rm olv-agent_wireguard-config 2>/dev/null || true
  docker volume rm olv-agent_agent-certs 2>/dev/null || true
  info "  Volumes removed"
else
  info "[2/3] Keeping data volumes (--keep-data)"
fi

info "[3/3] Removing application..."
if [ -d "$INSTALL_DIR" ]; then
  if confirm "Delete ${INSTALL_DIR}?"; then
    rm -rf "$INSTALL_DIR"
    info "  Application removed"
  fi
fi

echo ""
echo -e "${GREEN}Uninstall complete!${NC}"
echo ""
