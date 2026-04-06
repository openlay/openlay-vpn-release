#!/bin/bash
# =============================================================================
# OpenLay VPN Agent — Install Script
# Run as root: ./install.sh [options]
#
# Usage:
#   ./install.sh
#   ./install.sh -MANAGEMENT_URL=https://mgmt.example.com:3001 -ENROLLMENT_TOKEN=xxx
#   ./install.sh -MANAGEMENT_URL=https://mgmt:3001 -ENROLLMENT_TOKEN=xxx -MANAGEMENT_TOKEN=legacy
#   ./install.sh -GIT_REPO=https://github.com/org/repo.git -GIT_BRANCH=dev
# =============================================================================
set -e

# ---------------------------------------------------------------------------
# Parse arguments: -KEY=VALUE format
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    -MANAGEMENT_URL=*)  MANAGEMENT_URL="${arg#*=}" ;;
    -MANAGEMENT_TOKEN=*) MANAGEMENT_TOKEN="${arg#*=}" ;;
    -ENROLLMENT_TOKEN=*) ENROLLMENT_TOKEN="${arg#*=}" ;;
    -GIT_REPO=*)        GIT_REPO="${arg#*=}" ;;
    -GIT_BRANCH=*)      GIT_BRANCH="${arg#*=}" ;;
    -PORT=*)            AGENT_PORT="${arg#*=}" ;;
    -WG_CONFIG_DIR=*)   WG_CONFIG_DIR="${arg#*=}" ;;
    -h|--help)
      echo "Usage: ./install.sh [options]"
      echo ""
      echo "Options:"
      echo "  -MANAGEMENT_URL=URL     Management server URL (e.g. https://mgmt:3001)"
      echo "  -MANAGEMENT_TOKEN=TOKEN Token for legacy auth with management server"
      echo "  -ENROLLMENT_TOKEN=TOKEN  Enrollment token for cert-based auth (recommended)"
      echo "  -GIT_REPO=URL           Git repository URL"
      echo "  -GIT_BRANCH=BRANCH      Git branch (default: main)"
      echo "  -PORT=PORT              Agent listen port (default: 3000)"
      echo "  -WG_CONFIG_DIR=PATH     WireGuard config dir (default: /etc/wireguard)"
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
# Configuration (defaults, overridden by args above)
# ---------------------------------------------------------------------------
SERVICE_USER="olv-agent"
HOME_DIR="/home/${SERVICE_USER}"
APP_DIR="${HOME_DIR}/wireguard-agent-api"
SERVICE_NAME="olv-agent"
GIT_REPO="${GIT_REPO:-https://github.com/openlay/openlay-vpn.git}"
GIT_BRANCH="${GIT_BRANCH:-main}"
WG_CONFIG_DIR="${WG_CONFIG_DIR:-/etc/wireguard}"
AGENT_PORT="${AGENT_PORT:-3000}"
MANAGEMENT_URL="${MANAGEMENT_URL:-}"
# Auto-append /api if not present
if [ -n "$MANAGEMENT_URL" ] && [[ ! "$MANAGEMENT_URL" =~ /api$ ]]; then
  MANAGEMENT_URL="${MANAGEMENT_URL%/}/api"
fi
MANAGEMENT_TOKEN="${MANAGEMENT_TOKEN:-}"
ENROLLMENT_TOKEN="${ENROLLMENT_TOKEN:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ---------------------------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  error "This script must be run as root"
fi

info "=== OpenLay VPN Agent — Installer ==="
echo ""

# ---------------------------------------------------------------------------
# 1. Install dependencies
# ---------------------------------------------------------------------------
info "[1] Checking dependencies..."

# WireGuard
if ! command -v wg &>/dev/null; then
  warn "WireGuard not found. Installing..."
  if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq wireguard wireguard-tools
  elif command -v yum &>/dev/null; then
    yum install -y epel-release && yum install -y wireguard-tools
  elif command -v dnf &>/dev/null; then
    dnf install -y wireguard-tools
  else
    error "Cannot install WireGuard. Install manually and re-run."
  fi
fi

# Node.js
if ! command -v node &>/dev/null; then
  warn "Node.js not found. Installing..."
  if command -v apt-get &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -qq nodejs
  elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
    yum install -y nodejs 2>/dev/null || dnf install -y nodejs
  else
    error "Cannot install Node.js. Install manually and re-run."
  fi
fi

# Git
if ! command -v git &>/dev/null; then
  warn "Git not found. Installing..."
  apt-get install -y -qq git 2>/dev/null || yum install -y git 2>/dev/null || dnf install -y git 2>/dev/null
fi

# OpenSSL
if ! command -v openssl &>/dev/null; then
  error "OpenSSL is required but not found."
fi

info "  wg:      $(which wg)"
info "  node:    $(node --version)"
info "  git:     $(git --version)"
info "  openssl: $(openssl version)"

# ---------------------------------------------------------------------------
# 2. Create WireGuard interface (wg0)
# ---------------------------------------------------------------------------
info "[2] Creating WireGuard interface..."

WG_IFACE="wg0"
WG_PORT="51820"
WG_SUBNET="10.0.0.1/24"
WG_CONF="${WG_CONFIG_DIR}/${WG_IFACE}.conf"

mkdir -p "$WG_CONFIG_DIR"

if [ -f "$WG_CONF" ]; then
  info "  ${WG_CONF} already exists — skipping"
else
  # Generate server keypair
  WG_PRIVATE_KEY=$(wg genkey)
  WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)

  cat > "$WG_CONF" << WGEOF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
Address = ${WG_SUBNET}
ListenPort = ${WG_PORT}
SaveConfig = false
WGEOF

  chmod 600 "$WG_CONF"
  info "  Created ${WG_CONF}"
  info "  Server Public Key: ${WG_PUBLIC_KEY}"
  info "  Address: ${WG_SUBNET}"
  info "  Listen Port: ${WG_PORT}"
fi

# Bring up interface if not already
if ! ip link show "$WG_IFACE" &>/dev/null; then
  wg-quick up "$WG_IFACE" 2>/dev/null && \
    info "  Interface ${WG_IFACE} is UP" || \
    warn "  Could not bring up ${WG_IFACE} (will start after service runs)"
else
  info "  Interface ${WG_IFACE} already UP"
fi

# Enable on boot
systemctl enable wg-quick@${WG_IFACE} 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3. Create service user
# ---------------------------------------------------------------------------
info "[3] Creating service user '${SERVICE_USER}'..."

if id "$SERVICE_USER" &>/dev/null; then
  info "  User '${SERVICE_USER}' already exists"
else
  useradd -m -d "$HOME_DIR" -s /bin/bash "$SERVICE_USER"
  info "  User '${SERVICE_USER}' created with home ${HOME_DIR}"
fi

# ---------------------------------------------------------------------------
# 3. Pull source from git
# ---------------------------------------------------------------------------
info "[4] Pulling source code..."

if [ -d "$APP_DIR/.git" ]; then
  info "  Updating existing repo..."
  cd "$APP_DIR"
  sudo -u "$SERVICE_USER" git pull origin "$GIT_BRANCH" 2>/dev/null || {
    warn "  Git pull failed (might be local changes). Continuing with existing code."
  }
else
  info "  Cloning fresh repo..."
  sudo -u "$SERVICE_USER" git clone --depth 1 -b "$GIT_BRANCH" "$GIT_REPO" "$HOME_DIR/repo-tmp" 2>/dev/null || {
    # If repo requires auth or doesn't exist, copy local
    warn "  Git clone failed. Checking for local source..."
    if [ -d "./src" ]; then
      info "  Copying local source to ${APP_DIR}..."
      mkdir -p "$APP_DIR"
      cp -r ./src ./package.json ./package-lock.json ./.env.example "$APP_DIR/" 2>/dev/null
      cp ./olv-agent.service "$APP_DIR/" 2>/dev/null || true
    else
      error "No source available. Place source in current directory or fix git URL."
    fi
  }

  # If cloned full repo, extract agent dir
  if [ -d "$HOME_DIR/repo-tmp/vpn-agent/wireguard-agent-api" ]; then
    mkdir -p "$APP_DIR"
    cp -r "$HOME_DIR/repo-tmp/vpn-agent/wireguard-agent-api/"* "$APP_DIR/"
    rm -rf "$HOME_DIR/repo-tmp"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Install Node.js dependencies
# ---------------------------------------------------------------------------
info "[5] Installing Node.js dependencies..."
cd "$APP_DIR"
sudo -u "$SERVICE_USER" npm install --omit=dev 2>/dev/null || npm install --omit=dev

# ---------------------------------------------------------------------------
# 5. Generate API token (JWT-style random key)
# ---------------------------------------------------------------------------
info "[6] Generating API token..."
API_TOKEN=$(openssl rand -base64 32 | tr -d '=/+' | head -c 40)
info "  API Token: ${API_TOKEN}"

# ---------------------------------------------------------------------------
# 6. Generate TLS certificate
# ---------------------------------------------------------------------------
info "[7] Generating TLS certificate..."
CERT_DIR="${APP_DIR}/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
  info "  TLS cert already exists — skipping"
else
  openssl req -x509 \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 3650 -nodes \
    -subj "/CN=wireguard-agent" 2>/dev/null
  chmod 600 "$CERT_DIR/server.key"
  chmod 644 "$CERT_DIR/server.crt"
  info "  Self-signed cert generated (valid 10 years)"
fi

# ---------------------------------------------------------------------------
# 7. Create .env config
# ---------------------------------------------------------------------------
info "[8] Creating configuration..."

if [ -f "$APP_DIR/.env" ]; then
  info "  .env already exists — preserving"
else
  cat > "$APP_DIR/.env" << ENVEOF
# WireGuard Agent API Configuration
# Generated by install.sh on $(date -u +"%Y-%m-%d %H:%M:%S UTC")

# API server
PORT=${AGENT_PORT}
HOST=0.0.0.0

# TLS
TLS_CERT=./certs/server.crt
TLS_KEY=./certs/server.key

# Authentication
API_TOKEN=${API_TOKEN}

# WireGuard
WG_CONFIG_DIR=${WG_CONFIG_DIR}

# Audit
AUDIT_LOG_FILE=./audit.log
AUDIT_LOG_MAX=1000

# Management Server
MANAGEMENT_API_URL=${MANAGEMENT_URL}
MANAGEMENT_API_TOKEN=${MANAGEMENT_TOKEN}
MANAGEMENT_CA_CERT=./certs/management-ca.crt
HEARTBEAT_INTERVAL=30

# Enrollment token (for cert-based auth — recommended)
# Agent uses this to enroll and get a signed certificate from management CA.
# After enrollment, cert is used for auth and this token is no longer needed.
ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}

# IP Whitelist (empty = allow all, comma-separated)
ALLOWED_IPS=
ENVEOF
  chmod 600 "$APP_DIR/.env"
  info "  .env created with generated API token"
fi

# ---------------------------------------------------------------------------
# 8. Set permissions & install systemd service
# ---------------------------------------------------------------------------
info "[9] Setting permissions and installing service..."

# Own everything
chown -R "$SERVICE_USER:$SERVICE_USER" "$HOME_DIR"
chmod 640 "$APP_DIR/.env"
chmod 755 "$HOME_DIR"
chmod 755 "$APP_DIR"

# WireGuard config dir — agent needs full control
mkdir -p "$WG_CONFIG_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$WG_CONFIG_DIR"
chmod 700 "$WG_CONFIG_DIR"

# Set capabilities on wg binary so non-root can manage interfaces
WG_BIN=$(which wg 2>/dev/null)
if [ -n "$WG_BIN" ]; then
  setcap cap_net_admin+ep "$WG_BIN" 2>/dev/null && \
    info "  Set CAP_NET_ADMIN on $WG_BIN" || \
    warn "  Could not set capability on wg (using systemd AmbientCapabilities)"
fi

# SELinux: set correct contexts and create policy if needed
if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
  info "  SELinux detected ($(getenforce)). Configuring contexts..."

  # Set correct SELinux file contexts
  if command -v semanage &>/dev/null; then
    semanage fcontext -a -t bin_t "${APP_DIR}/src(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t etc_t "${APP_DIR}/.env" 2>/dev/null || true
    semanage fcontext -a -t cert_t "${APP_DIR}/certs(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t wireguard_etc_t "${WG_CONFIG_DIR}(/.*)?" 2>/dev/null || true
  fi
  restorecon -R "$HOME_DIR" 2>/dev/null || true
  restorecon -R "$WG_CONFIG_DIR" 2>/dev/null || true

  # Allow node to bind network and manage interfaces
  setsebool -P nis_enabled 1 2>/dev/null || true

  # Generate and apply policy from any existing denials
  if command -v audit2allow &>/dev/null; then
    ausearch -m avc -ts recent 2>/dev/null | audit2allow -M wgagent-policy 2>/dev/null && \
      semodule -i wgagent-policy.pp 2>/dev/null && \
      info "  SELinux policy applied" || true
    rm -f wgagent-policy.* 2>/dev/null
  fi
else
  info "  SELinux not active — skipping"
fi

# ---------------------------------------------------------------------------
# 9. Firewall & IP forwarding
# ---------------------------------------------------------------------------
info "[9] Configuring firewall and IP forwarding..."

# Enable IPv4 forwarding (persist across reboot)
if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
  sysctl -w net.ipv4.ip_forward=1
  if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  else
    sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
  fi
  info "  IPv4 forwarding enabled"
else
  info "  IPv4 forwarding already enabled"
fi

# Detect management server port from URL
MGMT_PORT=""
if [ -n "$MANAGEMENT_URL" ]; then
  MGMT_PORT=$(echo "$MANAGEMENT_URL" | sed -E 's|https?://[^:]+:?||' | sed 's|/.*||')
  [ -z "$MGMT_PORT" ] && MGMT_PORT="443"
fi

WG_SERVER_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)

# Firewall rules
if command -v firewall-cmd &>/dev/null; then
  # Start firewalld if installed but not running
  if ! systemctl is-active --quiet firewalld; then
    systemctl start firewalld 2>/dev/null && systemctl enable firewalld 2>/dev/null
    info "  Started firewalld"
  fi

  # firewalld (RHEL/Rocky/CentOS)
  info "  Configuring firewalld..."

  # Inbound
  firewall-cmd --permanent --add-port=51820/udp 2>/dev/null && info "    Inbound: 51820/udp (WireGuard)" || true
  firewall-cmd --permanent --add-port=${AGENT_PORT}/tcp 2>/dev/null && info "    Inbound: ${AGENT_PORT}/tcp (Agent API)" || true

  # Outbound: management server
  if [ -n "$MGMT_PORT" ]; then
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --dport "$MGMT_PORT" -j ACCEPT 2>/dev/null && \
      info "    Outbound: ${MGMT_PORT}/tcp (Management server)" || true
  fi
  # Outbound: HTTPS for IP detection + metadata
  firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --dport 443 -j ACCEPT 2>/dev/null && \
    info "    Outbound: 443/tcp (HTTPS)" || true
  firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p tcp --dport 80 -j ACCEPT 2>/dev/null && \
    info "    Outbound: 80/tcp (HTTP)" || true

  # NAT masquerade
  firewall-cmd --permanent --add-masquerade 2>/dev/null && info "    Masquerade (NAT)" || true

  # Forward: WireGuard peers
  firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i wg0 -o wg0 -j ACCEPT 2>/dev/null && \
    info "    Forward: wg0 <-> wg0 (peer-to-peer)" || true
  firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i wg0 -j ACCEPT 2>/dev/null && \
    info "    Forward: wg0 -> internet" || true
  firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && \
    info "    Forward: internet -> wg0 (established)" || true

  firewall-cmd --reload
  info "  firewalld configured"

elif command -v ufw &>/dev/null; then
  # ufw (Ubuntu/Debian)
  info "  Configuring ufw..."

  # Inbound
  ufw allow 51820/udp comment "WireGuard" 2>/dev/null && info "    Inbound: 51820/udp" || true
  ufw allow ${AGENT_PORT}/tcp comment "WireGuard Agent API" 2>/dev/null && info "    Inbound: ${AGENT_PORT}/tcp" || true

  # Outbound: management + HTTPS (ufw allows outbound by default, but explicit if restricted)
  ufw allow out 443/tcp comment "HTTPS outbound" 2>/dev/null || true
  ufw allow out 80/tcp comment "HTTP outbound" 2>/dev/null || true
  if [ -n "$MGMT_PORT" ] && [ "$MGMT_PORT" != "443" ]; then
    ufw allow out ${MGMT_PORT}/tcp comment "Management server" 2>/dev/null && \
      info "    Outbound: ${MGMT_PORT}/tcp (Management)" || true
  fi

  # Enable forwarding
  if ! grep -q "DEFAULT_FORWARD_POLICY=\"ACCEPT\"" /etc/default/ufw 2>/dev/null; then
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null
    info "    Forward policy set to ACCEPT"
  fi

  # NAT masquerade
  if [ -n "$WG_SERVER_IFACE" ] && [ -f /etc/ufw/before.rules ]; then
    if ! grep -q "WireGuard NAT" /etc/ufw/before.rules 2>/dev/null; then
      cat >> /etc/ufw/before.rules << UUEOF

# WireGuard NAT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/8 -o ${WG_SERVER_IFACE} -j MASQUERADE
COMMIT
UUEOF
      info "    NAT masquerade via ${WG_SERVER_IFACE}"
    fi
  fi

  ufw --force enable 2>/dev/null
  ufw reload 2>/dev/null
  info "  ufw configured"

elif command -v iptables &>/dev/null; then
  # Raw iptables fallback
  info "  Configuring iptables..."

  # Inbound
  iptables -C INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null
  info "    Inbound: 51820/udp (WireGuard)"
  iptables -C INPUT -p tcp --dport ${AGENT_PORT} -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --dport ${AGENT_PORT} -j ACCEPT 2>/dev/null
  info "    Inbound: ${AGENT_PORT}/tcp (Agent API)"

  # Outbound: management server
  if [ -n "$MGMT_PORT" ]; then
    iptables -C OUTPUT -p tcp --dport "$MGMT_PORT" -j ACCEPT 2>/dev/null || \
      iptables -A OUTPUT -p tcp --dport "$MGMT_PORT" -j ACCEPT 2>/dev/null
    info "    Outbound: ${MGMT_PORT}/tcp (Management)"
  fi
  iptables -C OUTPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
  info "    Outbound: 443/tcp (HTTPS)"
  iptables -C OUTPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || \
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
  info "    Outbound: 80/tcp (HTTP)"

  # Forward: WireGuard peers
  iptables -C FORWARD -i wg0 -o wg0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT 2>/dev/null
  info "    Forward: wg0 <-> wg0"
  iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null
  info "    Forward: wg0 -> internet"
  iptables -C FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
  info "    Forward: internet -> wg0 (established)"

  # NAT masquerade
  if [ -n "$WG_SERVER_IFACE" ]; then
    iptables -t nat -C POSTROUTING -s 10.0.0.0/8 -o "$WG_SERVER_IFACE" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o "$WG_SERVER_IFACE" -j MASQUERADE 2>/dev/null
    info "    NAT masquerade via ${WG_SERVER_IFACE}"
  fi

  # Persist
  if command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables.rules 2>/dev/null || true
    info "  iptables rules saved to /etc/iptables.rules"
  fi
  info "  iptables configured"

else
  warn "  No firewall tool found (firewalld/ufw/iptables). Configure manually."
  warn "  Required ports: 51820/udp (in), ${AGENT_PORT}/tcp (in), 443/tcp (out), ${MGMT_PORT}/tcp (out)"
fi

# Install systemd service
if [ -f "$APP_DIR/olv-agent.service" ]; then
  # Update paths in service file
  sed -i "s|WorkingDirectory=.*|WorkingDirectory=${APP_DIR}|" "$APP_DIR/olv-agent.service"
  sed -i "s|EnvironmentFile=.*|EnvironmentFile=${APP_DIR}/.env|" "$APP_DIR/olv-agent.service"
  sed -i "s|ReadWritePaths=.*|ReadWritePaths=${WG_CONFIG_DIR} ${APP_DIR}|" "$APP_DIR/olv-agent.service"

  cp "$APP_DIR/olv-agent.service" "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  sleep 2

  if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "  Service started successfully"
  else
    warn "  Service failed to start. Attempting SELinux fix..."

    # Retry: generate policy from fresh denials
    if command -v audit2allow &>/dev/null; then
      sleep 1
      ausearch -m avc -ts recent 2>/dev/null | audit2allow -M wgagent-policy 2>/dev/null && \
        semodule -i wgagent-policy.pp 2>/dev/null
      rm -f wgagent-policy.* 2>/dev/null
      systemctl restart "$SERVICE_NAME"
      sleep 2
    fi

    if systemctl is-active --quiet "$SERVICE_NAME"; then
      info "  Service started after SELinux fix"
    else
      warn "  Service still failing. Check: journalctl -u ${SERVICE_NAME} -n 20"
      warn "  If SELinux issue, try: setenforce 0 && systemctl restart ${SERVICE_NAME}"
    fi
  fi
else
  warn "  Service file not found. Create manually or copy olv-agent.service"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "==========================================="
echo -e "${GREEN}Installation complete!${NC}"
echo "==========================================="
echo ""
echo "  User:        ${SERVICE_USER}"
echo "  Home:        ${HOME_DIR}"
echo "  App:         ${APP_DIR}"
echo "  Config:      ${APP_DIR}/.env"
echo "  WG Config:   ${WG_CONFIG_DIR}"
echo "  API Token:   ${API_TOKEN}"
echo "  TLS Cert:    ${CERT_DIR}/server.crt"
echo ""
echo "  Status:      systemctl status ${SERVICE_NAME}"
echo "  Logs:        journalctl -u ${SERVICE_NAME} -f"
echo "  Restart:     systemctl restart ${SERVICE_NAME}"
echo ""
echo "Next steps:"
echo "  1. Edit ${APP_DIR}/.env — set MANAGEMENT_API_URL and MANAGEMENT_API_TOKEN"
echo "  2. If management uses self-signed cert, copy it to ${CERT_DIR}/management-ca.crt"
echo "  3. systemctl restart ${SERVICE_NAME}"
echo ""
