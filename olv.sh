#!/bin/bash
# =============================================================================
# OpenLay VPN — Unified Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh | bash -s -- install olv-management
#   curl -fsSL https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh | bash -s -- install olv-agent
#
# Or clone and run locally:
#   ./olv.sh install olv-management
#   ./olv.sh update olv-management
#   ./olv.sh uninstall olv-management
#
#   ./olv.sh install olv-agent
#   ./olv.sh update olv-agent
#   ./olv.sh uninstall olv-agent
# =============================================================================
set -e

REPO_URL="https://github.com/openlay/openlay-vpn-release.git"
REPO_BRANCH="main"
INSTALL_DIR="/opt/openlay-vpn-release"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

ACTION="${1:-}"
PACKAGE="${2:-}"

usage() {
  echo ""
  echo -e "${CYAN}OpenLay VPN — Unified Installer${NC}"
  echo ""
  echo "Usage: $0 <action> <package>"
  echo ""
  echo "Actions:"
  echo "  install     Install a package"
  echo "  update      Update an existing installation"
  echo "  uninstall   Remove a package"
  echo "  init-root   Create root admin account (olv-management only)"
  echo ""
  echo "Packages:"
  echo "  olv-management   Management server + App API + Dashboard"
  echo "  olv-agent        WireGuard agent (Docker)"
  echo ""
  echo "Examples:"
  echo "  $0 install olv-management"
  echo "  $0 init-root olv-management"
  echo "  $0 install olv-agent"
  echo "  $0 update olv-management"
  echo "  $0 uninstall olv-agent"
  echo ""
  exit 1
}

if [ -z "$ACTION" ] || [ -z "$PACKAGE" ]; then
  usage
fi

if [ "$EUID" -ne 0 ]; then
  error "This script must be run as root (use sudo)"
fi

# ---------------------------------------------------------------------------
# Ensure git is available
# ---------------------------------------------------------------------------
if ! command -v git &>/dev/null; then
  info "Installing git..."
  if command -v apt-get &>/dev/null; then
    apt-get install -y -qq git
  elif command -v dnf &>/dev/null; then
    dnf install -y git
  elif command -v yum &>/dev/null; then
    yum install -y git
  else
    error "Cannot install git. Install manually and re-run."
  fi
fi

# ---------------------------------------------------------------------------
# Download / update release repo
# ---------------------------------------------------------------------------
ORIGINAL_DIR="$(pwd)"

if [ -d "$INSTALL_DIR/.git" ]; then
  info "Updating release files..."
  cd "$INSTALL_DIR"
  git pull origin "$REPO_BRANCH" 2>/dev/null || warn "Git pull failed. Using existing files."
else
  info "Downloading release files..."
  rm -rf "$INSTALL_DIR"
  git clone --depth 1 -b "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>&1 || \
    error "Failed to download from ${REPO_URL}"
fi

cd "$ORIGINAL_DIR"

# ---------------------------------------------------------------------------
# Route to package script
# ---------------------------------------------------------------------------
case "$PACKAGE" in
  olv-management)
    SCRIPT_DIR="$INSTALL_DIR/olv-management/linux"
    case "$ACTION" in
      install)
        [ -f "$SCRIPT_DIR/install.sh" ] || error "install.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/install.sh" "${@:3}"
        ;;
      update)
        [ -f "$SCRIPT_DIR/update.sh" ] || error "update.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/update.sh" "${@:3}"
        ;;
      uninstall)
        [ -f "$SCRIPT_DIR/uninstall.sh" ] || error "uninstall.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/uninstall.sh" "${@:3}"
        ;;
      init-root)
        [ -f "$SCRIPT_DIR/init-root.sh" ] || error "init-root.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/init-root.sh" "${@:3}"
        ;;
      *)
        error "Unknown action: $ACTION (use install, update, uninstall, or init-root)"
        ;;
    esac
    ;;

  olv-agent)
    SCRIPT_DIR="$INSTALL_DIR/olv-agent-dkr"
    case "$ACTION" in
      install)
        [ -f "$SCRIPT_DIR/install.sh" ] || error "install.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/install.sh" "${@:3}"
        ;;
      update)
        [ -f "$SCRIPT_DIR/update.sh" ] || error "update.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/update.sh" "${@:3}"
        ;;
      uninstall)
        [ -f "$SCRIPT_DIR/uninstall.sh" ] || error "uninstall.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/uninstall.sh" "${@:3}"
        ;;
      *)
        error "Unknown action: $ACTION (use install, update, or uninstall)"
        ;;
    esac
    ;;

  *)
    error "Unknown package: $PACKAGE (use olv-management or olv-agent)"
    ;;
esac

cd "$ORIGINAL_DIR"
