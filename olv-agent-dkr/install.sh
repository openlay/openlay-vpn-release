#!/bin/bash
# =============================================================================
# OpenLay VPN Agent (Docker) — Install Script
# Run as root: ./install.sh [options]
#
# Usage:
#   ./install.sh
#   ./install.sh -MANAGEMENT_URL=https://mng.example.com:3084 -TOKEN=xxx
# =============================================================================
set -e

for arg in "$@"; do
  case "$arg" in
    -MANAGEMENT_URL=*) MANAGEMENT_URL="${arg#*=}" ;;
    -TOKEN=*)          ENROLLMENT_TOKEN="${arg#*=}" ;;
    -WG_PORT=*)        WG_PORT="${arg#*=}" ;;
    -h|--help)
      echo "Usage: ./install.sh [options]"
      echo ""
      echo "Options:"
      echo "  -MANAGEMENT_URL=URL   Management server URL (e.g. https://mng.example.com:3084)"
      echo "  -TOKEN=TOKEN          Enrollment token from management dashboard"
      echo "  -WG_PORT=PORT         WireGuard listen port (default: 51820)"
      echo ""
      exit 0
      ;;
    *) echo "Unknown option: $arg (use --help)"; exit 1 ;;
  esac
done

INSTALL_DIR="/opt/olv-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

ask() {
  local var_name="$1" prompt="$2" default="$3"
  local current="${!var_name}"
  if [ -n "$current" ]; then return; fi
  if [ -n "$default" ]; then
    read -rp "$(echo -e "${CYAN}?${NC}") ${prompt} [${default}]: " input < /dev/tty
    eval "$var_name=\"${input:-$default}\""
  else
    read -rp "$(echo -e "${CYAN}?${NC}") ${prompt}: " input < /dev/tty
    eval "$var_name=\"$input\""
  fi
}

if [ "$EUID" -ne 0 ]; then error "This script must be run as root"; fi

echo ""
echo "==========================================="
echo -e "${GREEN}  OpenLay VPN Agent (Docker) — Installer${NC}"
echo "==========================================="
echo ""

ask MANAGEMENT_URL  "Management server URL" "https://localhost:3084"
ask ENROLLMENT_TOKEN "Enrollment token" ""

WG_PORT="${WG_PORT:-51820}"

if [ -z "$MANAGEMENT_URL" ]; then error "Management URL is required"; fi
if [ -z "$ENROLLMENT_TOKEN" ]; then error "Enrollment token is required"; fi

# ---------------------------------------------------------------------------
# 1. Install Docker
# ---------------------------------------------------------------------------
info "[1/5] Checking Docker..."

if ! command -v docker &>/dev/null; then
  info "  Installing Docker..."
  # Try official script first
  if ! curl -fsSL https://get.docker.com | sh 2>/dev/null; then
    warn "  Official Docker install failed. Trying manual repo setup..."
    # Rocky/RHEL: use centos repo as fallback (Docker doesn't always support latest Rocky)
    if command -v dnf &>/dev/null; then
      dnf install -y dnf-plugins-core 2>/dev/null || true
      # Remove broken repo if exists
      rm -f /etc/yum.repos.d/docker-ce.repo 2>/dev/null
      # Use centos stream as base (compatible with Rocky)
      RELEASEVER=$(rpm -E %rhel 2>/dev/null || echo "9")
      dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || true
      sed -i "s|\$releasever|${RELEASEVER}|g" /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
      dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif command -v yum &>/dev/null; then
      yum install -y yum-utils
      yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif command -v apt-get &>/dev/null; then
      apt-get install -y docker.io docker-compose-plugin 2>/dev/null || \
      apt-get install -y docker.io docker-compose
    else
      error "Cannot install Docker. Install manually and re-run."
    fi
  fi
  systemctl enable --now docker
fi

if ! docker compose version &>/dev/null 2>&1; then
  if ! docker-compose version &>/dev/null 2>&1; then
    warn "  Docker Compose not found. Installing plugin..."
    mkdir -p /usr/local/lib/docker/cli-plugins
    COMPOSE_URL="https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)"
    curl -fsSL "$COMPOSE_URL" -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  fi
fi

info "  Docker: $(docker --version)"

# ---------------------------------------------------------------------------
# 2. Enable IP forwarding
# ---------------------------------------------------------------------------
info "[2/5] Enabling IP forwarding..."

sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
info "  IP forwarding enabled"

# ---------------------------------------------------------------------------
# 3. Copy application files
# ---------------------------------------------------------------------------
info "[3/5] Installing application files..."

mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/Dockerfile" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/docker-compose.yml" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/docker-entrypoint.sh" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/package.json" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/package-lock.json" "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/docker-entrypoint.sh"
info "  Files installed: ${INSTALL_DIR}"

# ---------------------------------------------------------------------------
# 4. Create .env
# ---------------------------------------------------------------------------
info "[4/5] Creating configuration..."

if [ ! -f "$INSTALL_DIR/.env" ]; then
  cat > "$INSTALL_DIR/.env" << ENVEOF
MANAGEMENT_API_URL=${MANAGEMENT_URL}/api
ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}
WG_CONFIG_DIR=/etc/wireguard
AUDIT_LOG_FILE=/var/log/olv-agent-audit.log
HEARTBEAT_INTERVAL=30000
ENVEOF
  info "  .env created"
else
  info "  .env exists — preserving"
fi

# ---------------------------------------------------------------------------
# 5. Build and start
# ---------------------------------------------------------------------------
info "[5/5] Building and starting agent..."

cd "$INSTALL_DIR"

# Open WireGuard port
set +e
if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port=51820-51830/udp 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null
elif command -v ufw &>/dev/null; then
  ufw allow 51820:51830/udp 2>/dev/null || true
fi
set -e

docker compose build 2>&1 | tail -3
docker compose up -d 2>&1

sleep 3

if docker compose ps --format json 2>/dev/null | grep -q '"running"'; then
  RUNNING=true
elif docker compose ps 2>/dev/null | grep -q "Up"; then
  RUNNING=true
else
  RUNNING=false
fi

cd "$OLDPWD"

echo ""
echo "==========================================="
if [ "$RUNNING" = true ]; then
  echo -e "${GREEN}Agent installed and running!${NC}"
else
  echo -e "${YELLOW}Agent installed but may not be running.${NC}"
  echo "  Check: cd ${INSTALL_DIR} && docker compose logs"
fi
echo "==========================================="
echo ""
echo "  Install dir:    ${INSTALL_DIR}"
echo "  VPN ports:      51820-51830/udp"
echo "  Management:     ${MANAGEMENT_URL}"
echo ""
echo "  Logs:    cd ${INSTALL_DIR} && docker compose logs -f"
echo "  Restart: cd ${INSTALL_DIR} && docker compose restart"
echo "  Stop:    cd ${INSTALL_DIR} && docker compose down"
echo ""
