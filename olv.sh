#!/bin/sh
# =============================================================================
# OpenLay VPN — Unified Installer
#
# Works on both Linux (management server) and FreeBSD (agent). POSIX sh, no
# bashisms — FreeBSD base doesn't ship bash.
#
# `olv-agent` dispatches to the native FreeBSD agent (olv-agent-bsd). The old
# Linux Docker agent (olv-agent-dkr) is no longer supported.
#
# Usage (Linux management server):
#   curl -fsSL https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh -o olv.sh
#   chmod +x olv.sh
#   sudo ./olv.sh install olv-management
#
# Usage (FreeBSD agent — run as root; no sudo on FreeBSD base):
#   fetch -qo olv.sh https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh
#   chmod +x olv.sh
#   ./olv.sh install olv-agent
# =============================================================================
set -eu

REPO_URL="https://github.com/openlay/openlay-vpn-release.git"
REPO_BRANCH="main"
INSTALL_DIR="/opt/openlay-vpn-release"

# Minimal color helpers. `printf %b` is POSIX; `echo -e` is not.
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { printf "%b[INFO]%b %s\n"  "$GREEN"  "$NC" "$1"; }
warn()  { printf "%b[WARN]%b %s\n"  "$YELLOW" "$NC" "$1"; }
error() { printf "%b[ERROR]%b %s\n" "$RED"    "$NC" "$1" >&2; exit 1; }

ACTION="${1:-}"
PACKAGE="${2:-}"

usage() {
  printf "\n%bOpenLay VPN — Unified Installer%b\n\n" "$CYAN" "$NC"
  cat <<EOF
Usage: $0 <action> <package>

Actions:
  install     Install a package
  update      Update an existing installation
  uninstall   Remove a package
  init-root   Create root admin account (olv-management only)

Packages:
  olv-management   Management server + App API (Linux)
  olv-agent        WireGuard agent (FreeBSD, native)

Examples:
  $0 install olv-management
  $0 init-root olv-management
  $0 install olv-agent
  $0 update olv-management
  $0 uninstall olv-agent

EOF
  exit 1
}

if [ -z "$ACTION" ] || [ -z "$PACKAGE" ]; then
  usage
fi

# POSIX-portable root check (no $EUID on FreeBSD /bin/sh).
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    error "This script must be run as root (use sudo)"
  else
    error "This script must be run as root (log in as root or 'su -')"
  fi
fi

# ---------------------------------------------------------------------------
# Ensure git is available
# ---------------------------------------------------------------------------
if ! command -v git >/dev/null 2>&1; then
  info "Installing git..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq git
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y git
  elif command -v pkg >/dev/null 2>&1; then
    # FreeBSD
    pkg install -y git
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

# Drop the first two args (ACTION + PACKAGE) so "$@" forwards only the rest
# to sub-installers. POSIX replacement for bash's "${@:3}".
shift 2 || true

# ---------------------------------------------------------------------------
# Route to package script
# ---------------------------------------------------------------------------
case "$PACKAGE" in
  olv-management)
    SCRIPT_DIR="$INSTALL_DIR/olv-management/linux"
    case "$ACTION" in
      install)
        [ -f "$SCRIPT_DIR/install.sh" ] || error "install.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/install.sh" "$@"
        ;;
      update)
        [ -f "$SCRIPT_DIR/update.sh" ] || error "update.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/update.sh" "$@"
        ;;
      uninstall)
        [ -f "$SCRIPT_DIR/uninstall.sh" ] || error "uninstall.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/uninstall.sh" "$@"
        ;;
      init-root)
        [ -f "$SCRIPT_DIR/init-root.sh" ] || error "init-root.sh not found in $SCRIPT_DIR"
        bash "$SCRIPT_DIR/init-root.sh" "$@"
        ;;
      *)
        error "Unknown action: $ACTION (use install, update, uninstall, or init-root)"
        ;;
    esac
    ;;

  olv-agent)
    # Always dispatch to the FreeBSD agent — Linux Docker agent is retired.
    SCRIPT_DIR="$INSTALL_DIR/olv-agent-bsd"
    # olv-agent-bsd scripts are /bin/sh, not bash.
    case "$ACTION" in
      install)
        [ -f "$SCRIPT_DIR/install.sh" ] || error "install.sh not found in $SCRIPT_DIR"
        sh "$SCRIPT_DIR/install.sh" "$@"
        ;;
      update)
        # olv-agent-bsd install.sh is idempotent — preserves agent.conf + certs.
        [ -f "$SCRIPT_DIR/install.sh" ] || error "install.sh not found in $SCRIPT_DIR"
        sh "$SCRIPT_DIR/install.sh" "$@"
        ;;
      uninstall)
        [ -f "$SCRIPT_DIR/uninstall.sh" ] || error "uninstall.sh not found in $SCRIPT_DIR"
        sh "$SCRIPT_DIR/uninstall.sh" "$@"
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
