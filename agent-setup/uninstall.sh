#!/bin/bash
# =============================================================================
# OpenLay VPN Agent — Uninstall Script
# Run as root: ./uninstall.sh [options]
#
# Usage:
#   ./uninstall.sh              # Interactive — asks before each step
#   ./uninstall.sh --force      # Remove everything without asking
#   ./uninstall.sh --keep-wg    # Remove agent but keep WireGuard config & interface
#   ./uninstall.sh --keep-user  # Remove agent but keep olv-agent user
# =============================================================================
set -e

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
FORCE=false
KEEP_WG=false
KEEP_USER=false

for arg in "$@"; do
  case "$arg" in
    --force)     FORCE=true ;;
    --keep-wg)   KEEP_WG=true ;;
    --keep-user) KEEP_USER=true ;;
    -h|--help)
      echo "Usage: ./uninstall.sh [options]"
      echo ""
      echo "Options:"
      echo "  --force      Remove everything without asking"
      echo "  --keep-wg    Keep WireGuard config and interface"
      echo "  --keep-user  Keep wgagent system user"
      echo ""
      exit 0
      ;;
    *)
      echo "Unknown option: $arg (use --help)"
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SERVICE_USER="olv-agent"
HOME_DIR="/home/${SERVICE_USER}"
APP_DIR="${HOME_DIR}/wireguard-agent-api"
SERVICE_NAME="olv-agent"
WG_CONFIG_DIR="/etc/wireguard"
WG_IFACE="wg0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

confirm() {
  if [ "$FORCE" = true ]; then return 0; fi
  read -p "  $1 [y/N] " -n 1 -r
  echo
  [[ $REPLY =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  error "This script must be run as root"
fi

echo ""
echo -e "${RED}=== OpenLay VPN Agent — Uninstaller ===${NC}"
echo ""
if [ "$FORCE" != true ]; then
  echo "This will remove the OpenLay VPN Agent and related configuration."
  echo "Options: --keep-wg (keep WireGuard), --keep-user (keep user), --force (no prompts)"
  echo ""
fi

# ---------------------------------------------------------------------------
# 1. Stop and disable service
# ---------------------------------------------------------------------------
info "[1/7] Stopping service..."

if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  systemctl stop "$SERVICE_NAME"
  info "  Service stopped"
else
  info "  Service not running"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
  systemctl disable "$SERVICE_NAME" 2>/dev/null
  info "  Service disabled"
fi

if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl daemon-reload
  info "  Service file removed"
fi

# ---------------------------------------------------------------------------
# 2. Bring down WireGuard interface
# ---------------------------------------------------------------------------
if [ "$KEEP_WG" != true ]; then
  info "[2/7] Removing WireGuard interface..."

  if ip link show "$WG_IFACE" &>/dev/null; then
    if confirm "Bring down ${WG_IFACE} interface?"; then
      wg-quick down "$WG_IFACE" 2>/dev/null && \
        info "  Interface ${WG_IFACE} brought down" || \
        warn "  Could not bring down ${WG_IFACE}"
    fi
  else
    info "  Interface ${WG_IFACE} not active"
  fi

  # Disable on boot
  systemctl disable wg-quick@${WG_IFACE} 2>/dev/null || true
else
  info "[2/7] Keeping WireGuard interface (--keep-wg)"
fi

# ---------------------------------------------------------------------------
# 3. Remove WireGuard config
# ---------------------------------------------------------------------------
if [ "$KEEP_WG" != true ]; then
  info "[3/7] Removing WireGuard config..."

  if [ -d "$WG_CONFIG_DIR" ] && [ "$(ls -A $WG_CONFIG_DIR 2>/dev/null)" ]; then
    if confirm "Delete all files in ${WG_CONFIG_DIR}?"; then
      rm -rf "${WG_CONFIG_DIR:?}"/*
      info "  WireGuard config files removed"
    else
      info "  Skipped"
    fi
  else
    info "  No config files found"
  fi
else
  info "[3/7] Keeping WireGuard config (--keep-wg)"
fi

# ---------------------------------------------------------------------------
# 4. Remove application directory
# ---------------------------------------------------------------------------
info "[4/7] Removing application..."

if [ -d "$APP_DIR" ]; then
  if confirm "Delete ${APP_DIR}?"; then
    rm -rf "$APP_DIR"
    info "  Application removed"
  fi
else
  info "  Application directory not found"
fi

# ---------------------------------------------------------------------------
# 5. Remove user
# ---------------------------------------------------------------------------
if [ "$KEEP_USER" != true ]; then
  info "[5/7] Removing service user..."

  if id "$SERVICE_USER" &>/dev/null; then
    if confirm "Delete user '${SERVICE_USER}' and home directory?"; then
      userdel -r "$SERVICE_USER" 2>/dev/null && \
        info "  User '${SERVICE_USER}' and home removed" || {
          userdel "$SERVICE_USER" 2>/dev/null
          rm -rf "$HOME_DIR" 2>/dev/null
          info "  User removed, home cleaned up"
        }
    fi
  else
    info "  User '${SERVICE_USER}' not found"
  fi
else
  info "[5/7] Keeping user (--keep-user)"
fi

# ---------------------------------------------------------------------------
# 6. Revert firewall rules
# ---------------------------------------------------------------------------
info "[6/7] Reverting firewall rules..."

WG_SERVER_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)

if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
  info "  Reverting firewalld..."
  # Inbound
  firewall-cmd --permanent --remove-port=51820/udp 2>/dev/null || true
  firewall-cmd --permanent --remove-port=3000/tcp 2>/dev/null || true
  # Outbound
  firewall-cmd --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
  firewall-cmd --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  firewall-cmd --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --dport 3001 -j ACCEPT 2>/dev/null || true
  # Masquerade
  firewall-cmd --permanent --remove-masquerade 2>/dev/null || true
  # Forward
  firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i wg0 -o wg0 -j ACCEPT 2>/dev/null || true
  firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT 2>/dev/null || true
  firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null
  info "  firewalld rules removed"

elif command -v ufw &>/dev/null; then
  info "  Reverting ufw..."
  ufw delete allow 51820/udp 2>/dev/null || true
  ufw delete allow 3000/tcp 2>/dev/null || true
  ufw delete allow out 443/tcp 2>/dev/null || true
  ufw delete allow out 80/tcp 2>/dev/null || true
  ufw delete allow out 3001/tcp 2>/dev/null || true
  # Revert forward policy
  if grep -q "DEFAULT_FORWARD_POLICY=\"ACCEPT\"" /etc/default/ufw 2>/dev/null; then
    sed -i 's/DEFAULT_FORWARD_POLICY="ACCEPT"/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw 2>/dev/null
  fi
  # Remove NAT masquerade from before.rules
  if grep -q "WireGuard NAT" /etc/ufw/before.rules 2>/dev/null; then
    sed -i '/# WireGuard NAT/,/COMMIT/d' /etc/ufw/before.rules 2>/dev/null
  fi
  ufw reload 2>/dev/null
  info "  ufw rules removed"

elif command -v iptables &>/dev/null; then
  info "  Reverting iptables..."
  # Inbound
  iptables -D INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -p tcp --dport 3000 -j ACCEPT 2>/dev/null || true
  # Outbound
  iptables -D OUTPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
  iptables -D OUTPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  iptables -D OUTPUT -p tcp --dport 3001 -j ACCEPT 2>/dev/null || true
  # Forward
  iptables -D FORWARD -i wg0 -o wg0 -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  # NAT
  if [ -n "$WG_SERVER_IFACE" ]; then
    iptables -t nat -D POSTROUTING -s 10.0.0.0/8 -o "$WG_SERVER_IFACE" -j MASQUERADE 2>/dev/null || true
  fi
  iptables -t nat -D POSTROUTING -s 10.0.0.0/8 -j MASQUERADE 2>/dev/null || true
  # Persist
  if command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables.rules 2>/dev/null || true
  fi
  info "  iptables rules removed"
fi

# ---------------------------------------------------------------------------
# 7. Revert SELinux policy
# ---------------------------------------------------------------------------
info "[7/7] Reverting SELinux..."

if command -v semodule &>/dev/null; then
  semodule -r wgagent-policy 2>/dev/null && \
    info "  SELinux policy removed" || \
    info "  No SELinux policy to remove"
  if command -v semanage &>/dev/null; then
    semanage fcontext -d "${APP_DIR}/src(/.*)?" 2>/dev/null || true
    semanage fcontext -d "${APP_DIR}/.env" 2>/dev/null || true
    semanage fcontext -d "${APP_DIR}/certs(/.*)?" 2>/dev/null || true
  fi
else
  info "  SELinux not available"
fi

# ---------------------------------------------------------------------------
# Note about IP forwarding
# ---------------------------------------------------------------------------
echo ""
warn "Note: IPv4 forwarding (net.ipv4.ip_forward) was NOT disabled."
warn "If you want to disable it:"
warn "  sysctl -w net.ipv4.ip_forward=0"
warn "  Edit /etc/sysctl.conf and set net.ipv4.ip_forward = 0"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "==========================================="
echo -e "${GREEN}Uninstall complete!${NC}"
echo "==========================================="
echo ""
echo "  Removed:"
echo "    - systemd service: ${SERVICE_NAME}"
[ "$KEEP_WG" != true ] && echo "    - WireGuard interface: ${WG_IFACE}" && echo "    - WireGuard config: ${WG_CONFIG_DIR}"
[ "$KEEP_USER" != true ] && echo "    - System user: ${SERVICE_USER}" && echo "    - Home directory: ${HOME_DIR}"
echo "    - Firewall rules"
echo "    - SELinux policy"
echo ""
echo "  Kept:"
[ "$KEEP_WG" = true ] && echo "    - WireGuard interface and config (--keep-wg)"
[ "$KEEP_USER" = true ] && echo "    - System user ${SERVICE_USER} (--keep-user)"
echo "    - IPv4 forwarding setting"
echo ""
