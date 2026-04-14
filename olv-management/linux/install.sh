#!/bin/bash
# =============================================================================
# OpenLay VPN Management Server + App API — Install Script (Release Package)
# Run as root: ./install.sh [options]
#
# Installs both services on the same server:
#   - olv-management (port 3084) — Admin dashboard + WebSocket agent hub
#   - olv-app-api (port 443) — VPN client API
#
# Usage:
#   ./install.sh
#   ./install.sh -DOMAIN=mng.livevpn.com
#   ./install.sh -DB_URL=postgres://user:pass@localhost:5432/dbname
# =============================================================================
set -e

for arg in "$@"; do
  case "$arg" in
    -DOMAIN=*)          DOMAIN="${arg#*=}" ;;
    -DB_URL=*)          DB_URL="${arg#*=}" ;;
    -DB_NAME=*)         DB_NAME="${arg#*=}" ;;
    -JWT_SECRET=*)      JWT_SECRET="${arg#*=}" ;;
    -APPLE_CLIENT_IDS=*) APPLE_CLIENT_IDS="${arg#*=}" ;;
    -APPLE_TEAM_ID=*)   APPLE_TEAM_ID="${arg#*=}" ;;
    -h|--help)
      echo "Usage: ./install.sh [options]"
      echo ""
      echo "Options:"
      echo "  -DOMAIN=DOMAIN           Domain name (e.g. mng.livevpn.com)"
      echo "  -DB_URL=URL              PostgreSQL connection URL"
      echo "  -DB_NAME=NAME            Database name (default: wireguard_management)"
      echo "  -JWT_SECRET=SECRET       JWT signing secret (auto-generated if not set)"
      echo "  -APPLE_CLIENT_IDS=IDS    Apple client IDs (comma-separated)"
      echo "  -APPLE_TEAM_ID=ID        Apple team ID"
      echo ""
      exit 0
      ;;
    *) echo "Unknown option: $arg (use --help)"; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVICE_USER="olv-management"
HOME_DIR="/home/${SERVICE_USER}"
MGMT_DIR="${HOME_DIR}/wireguard-management"
APP_API_DIR="${HOME_DIR}/app-api"
MGMT_SERVICE="olv-management"
APP_API_SERVICE="olv-app-api"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Prompt for a value if not already set.
# Usage: ask VAR_NAME "Prompt text" "default_value"
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
echo -e "${GREEN}  OpenLay VPN Management — Installer${NC}"
echo "==========================================="
echo ""

# ---------------------------------------------------------------------------
# Interactive prompts (skipped if value passed via CLI args)
# ---------------------------------------------------------------------------
ask DOMAIN        "Domain name (e.g. mng.livevpn.com)" ""
ask DB_NAME       "Database name" "olv_management"
ask DB_URL        "PostgreSQL URL" "postgres://${SERVICE_USER}@127.0.0.1:5432/${DB_NAME}"
ask JWT_SECRET    "JWT secret (leave blank to auto-generate)" ""

APPLE_TEAM_ID="${APPLE_TEAM_ID:-4VG6UTF567}"
APPLE_CLIENT_IDS="${APPLE_CLIENT_IDS:-com.openlay.management}"

# Auto-generate JWT secret if left blank
if [ -z "$JWT_SECRET" ]; then
  JWT_SECRET=$(openssl rand -base64 32)
  info "JWT secret auto-generated"
fi

echo ""

# ---------------------------------------------------------------------------
# 1. Install dependencies
# ---------------------------------------------------------------------------
info "[1/10] Checking dependencies..."

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

if ! command -v openssl &>/dev/null; then
  warn "OpenSSL not found. Installing..."
  if command -v apt-get &>/dev/null; then
    apt-get install -y -qq openssl
  elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    yum install -y openssl 2>/dev/null || dnf install -y openssl
  else
    error "Cannot install OpenSSL. Install manually and re-run."
  fi
fi

info "  node: $(node --version)"

# ---------------------------------------------------------------------------
# 2. Create service user
# ---------------------------------------------------------------------------
info "[2/10] Creating service user '${SERVICE_USER}'..."

if id "$SERVICE_USER" &>/dev/null; then
  info "  User already exists"
else
  useradd -m -d "$HOME_DIR" -s /bin/bash "$SERVICE_USER"
  info "  User created: ${HOME_DIR}"
fi

# ---------------------------------------------------------------------------
# 3. Copy application files (from release package)
# ---------------------------------------------------------------------------
info "[3/10] Installing application files..."

mkdir -p "$MGMT_DIR" "$APP_API_DIR"

# Management server
cp -r "$SCRIPT_DIR/server" "$MGMT_DIR/"
if [ -d "$SCRIPT_DIR/client/dist" ]; then
  mkdir -p "$MGMT_DIR/client"
  cp -r "$SCRIPT_DIR/client/dist" "$MGMT_DIR/client/"
fi
cp "$SCRIPT_DIR/package.json" "$MGMT_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/package-lock.json" "$MGMT_DIR/" 2>/dev/null || true
info "  Management server: ${MGMT_DIR}"

# App API
rm -rf "$APP_API_DIR/src" "$APP_API_DIR/package.json" "$APP_API_DIR/package-lock.json"
cp -r "$SCRIPT_DIR/app-api/src" "$APP_API_DIR/src"
cp "$SCRIPT_DIR/app-api/package.json" "$APP_API_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/app-api/package-lock.json" "$APP_API_DIR/" 2>/dev/null || true
info "  App API: ${APP_API_DIR}"

chown -R "$SERVICE_USER:$SERVICE_USER" "$HOME_DIR"

# ---------------------------------------------------------------------------
# 4. Install Node.js dependencies
# ---------------------------------------------------------------------------
info "[4/10] Installing dependencies..."

cd "$MGMT_DIR/server"
sudo -u "$SERVICE_USER" npm install --omit=dev 2>&1 | tail -1
info "  Management server deps installed"

cd "$APP_API_DIR"
sudo -u "$SERVICE_USER" npm install --omit=dev 2>&1 | tail -1
info "  App API deps installed"

# ---------------------------------------------------------------------------
# 5. Install + setup PostgreSQL
# ---------------------------------------------------------------------------
info "[5/10] Setting up PostgreSQL..."

if ! command -v psql &>/dev/null || ! command -v postgres &>/dev/null; then
  info "  Installing PostgreSQL..."
  if command -v yum &>/dev/null; then
    yum install -y postgresql-server postgresql
  elif command -v dnf &>/dev/null; then
    dnf install -y postgresql-server postgresql
  elif command -v apt-get &>/dev/null; then
    apt-get install -y -qq postgresql postgresql-client
  else
    error "Cannot install PostgreSQL. Install manually and re-run."
  fi
fi

if command -v postgresql-setup &>/dev/null; then
  postgresql-setup --initdb 2>/dev/null || true
fi

systemctl start postgresql 2>/dev/null || true
systemctl enable postgresql 2>/dev/null || true

for i in 1 2 3 4 5; do
  sudo -u postgres psql -c "SELECT 1;" 2>/dev/null && break
  sleep 2
done

PG_HBA=""
for f in /var/lib/pgsql/data/pg_hba.conf /etc/postgresql/*/main/pg_hba.conf; do
  [ -f "$f" ] && PG_HBA="$f" && break
done
if [ -n "$PG_HBA" ]; then
  # Remove any old entries for this user
  sed -i "/host all ${SERVICE_USER}/d" "$PG_HBA" 2>/dev/null || true
  # Insert trust rules at the TOP (before ident/peer rules that would override)
  sed -i "1i host all ${SERVICE_USER} ::1/128 trust" "$PG_HBA"
  sed -i "1i host all ${SERVICE_USER} 127.0.0.1/32 trust" "$PG_HBA"
  # Also allow local socket connections with trust
  sed -i "1i local all ${SERVICE_USER} trust" "$PG_HBA"
  systemctl reload postgresql 2>/dev/null
  info "  PostgreSQL access configured (trust for ${SERVICE_USER})"
fi

sudo -u postgres createuser -s "${SERVICE_USER}" 2>/dev/null || true
sudo -u postgres createdb -O "${SERVICE_USER}" "${DB_NAME}" 2>/dev/null || true

if psql -h 127.0.0.1 -U "${SERVICE_USER}" -d "${DB_NAME}" -c "SELECT 1;" &>/dev/null; then
  info "  Database ready: ${DB_NAME}"
else
  warn "  Database connection failed. Check PostgreSQL config."
fi

# ---------------------------------------------------------------------------
# 6. Generate TLS certificates
# ---------------------------------------------------------------------------
info "[6/10] Generating TLS certificates..."

for CERT_DIR in "$MGMT_DIR/certs" "$APP_API_DIR/certs"; do
  mkdir -p "$CERT_DIR"
  if [ ! -f "$CERT_DIR/key.pem" ] || [ ! -f "$CERT_DIR/cert.pem" ]; then
    CN="${DOMAIN:-openlay-management}"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
      -days 3650 -nodes -subj "/CN=${CN}" 2>/dev/null
    chmod 600 "$CERT_DIR/key.pem"
    info "  TLS cert generated: ${CERT_DIR}"
  else
    info "  TLS cert exists: ${CERT_DIR}"
  fi
done

# ---------------------------------------------------------------------------
# 7. Create .env configs
# ---------------------------------------------------------------------------
info "[7/10] Creating configuration files..."

MGMT_API_TOKEN=$(openssl rand -base64 32 | tr -d '=/+' | head -c 40)

if [ ! -f "$MGMT_DIR/.env" ]; then
  cat > "$MGMT_DIR/.env" << ENVEOF
DATABASE_URL=${DB_URL}
PORT=3084
JWT_SECRET=${JWT_SECRET}
APPLE_CLIENT_IDS=${APPLE_CLIENT_IDS}
APPLE_TEAM_ID=${APPLE_TEAM_ID}
MANAGEMENT_API_TOKEN=${MGMT_API_TOKEN}
TLS_CERT_DIR=./certs
ENVEOF
  info "  Management .env created"
else
  info "  Management .env exists — preserving"
  MGMT_API_TOKEN=$(grep MANAGEMENT_API_TOKEN "$MGMT_DIR/.env" 2>/dev/null | cut -d'=' -f2)
fi

if [ ! -f "$APP_API_DIR/.env" ]; then
  cat > "$APP_API_DIR/.env" << ENVEOF
DATABASE_URL=${DB_URL}
PORT=443
JWT_SECRET=${JWT_SECRET}
APPLE_CLIENT_IDS=${APPLE_CLIENT_IDS}
APPLE_TEAM_ID=${APPLE_TEAM_ID}
APP_ATTEST_PRODUCTION=false
MANAGEMENT_URL=https://localhost:3084
INTERNAL_API_KEY=${MGMT_API_TOKEN}
ENVEOF
  info "  App API .env created"
else
  info "  App API .env exists — preserving"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$HOME_DIR"

# ---------------------------------------------------------------------------
# 8. Install systemd services
# ---------------------------------------------------------------------------
info "[8/10] Installing systemd services..."

cat > "/etc/systemd/system/${MGMT_SERVICE}.service" << SVCEOF
[Unit]
Description=OpenLay VPN Management Server
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${MGMT_DIR}/server
ExecStart=/usr/bin/node src/index.js
EnvironmentFile=${MGMT_DIR}/.env
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=olv-management

[Install]
WantedBy=multi-user.target
SVCEOF

cat > "/etc/systemd/system/${APP_API_SERVICE}.service" << SVCEOF
[Unit]
Description=OpenLay VPN App API
After=network-online.target postgresql.service ${MGMT_SERVICE}.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_API_DIR}
ExecStart=/usr/bin/node src/index.js
EnvironmentFile=${APP_API_DIR}/.env
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=journal
StandardError=journal
SyslogIdentifier=olv-app-api

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable "$MGMT_SERVICE" "$APP_API_SERVICE"
info "  Services installed"

# ---------------------------------------------------------------------------
# 9. Firewall
# ---------------------------------------------------------------------------
info "[9/10] Configuring firewall..."

set +e
FIREWALL_OPENED=false
if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port=3084/tcp 2>/dev/null
  firewall-cmd --permanent --add-port=443/tcp 2>/dev/null
  firewall-cmd --reload 2>/dev/null
  FIREWALL_OPENED=true
  info "  firewalld: opened ports 3084/tcp, 443/tcp"
elif command -v ufw &>/dev/null; then
  ufw allow 3084/tcp 2>/dev/null
  ufw allow 443/tcp 2>/dev/null
  FIREWALL_OPENED=true
  info "  ufw: opened ports 3084/tcp, 443/tcp"
elif command -v iptables &>/dev/null; then
  iptables -C INPUT -p tcp --dport 3084 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 3084 -j ACCEPT 2>/dev/null
  iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
  iptables-save > /etc/iptables.rules 2>/dev/null || true
  FIREWALL_OPENED=true
  info "  iptables: opened ports 3084/tcp, 443/tcp"
fi
if [ "$FIREWALL_OPENED" = false ]; then
  warn "  No firewall detected. Make sure ports 3084/tcp and 443/tcp are accessible."
  warn "  If using cloud (AWS/GCP/Azure), open these ports in your Security Group."
fi
set -e

# ---------------------------------------------------------------------------
# 10. Start services
# ---------------------------------------------------------------------------
info "[10/10] Starting services..."

chmod 755 "$HOME_DIR" "$MGMT_DIR" "$APP_API_DIR" "$MGMT_DIR/server" 2>/dev/null || true
restorecon -R "$HOME_DIR" 2>/dev/null || true

set +e
if command -v getenforce &>/dev/null && [ "$(getenforce)" = "Enforcing" ]; then
  info "  SELinux enforcing — building policy..."
  yum install -y policycoreutils-python-utils 2>/dev/null || \
  dnf install -y policycoreutils-python-utils 2>/dev/null || true
  for SVC in "$MGMT_SERVICE" "$APP_API_SERVICE"; do
    for i in 1 2 3 4 5; do
      systemctl start "$SVC" 2>/dev/null; sleep 2
      if systemctl is-active --quiet "$SVC"; then break; fi
      if command -v audit2allow &>/dev/null; then
        ausearch -m avc -ts recent 2>/dev/null | audit2allow -M olv-svc-$i 2>/dev/null && \
          semodule -i olv-svc-$i.pp 2>/dev/null || true
        rm -f olv-svc-$i.* 2>/dev/null
      fi
    done
  done
else
  systemctl restart "$MGMT_SERVICE"; sleep 3
  systemctl restart "$APP_API_SERVICE"; sleep 3
fi
set -e

echo ""
echo "==========================================="
echo -e "${GREEN}Installation complete!${NC}"
echo "==========================================="
echo ""
echo "  Management:  https://${DOMAIN:-localhost}:3084"
echo "  App API:     https://${DOMAIN:-localhost}:443"
echo ""
echo "  Status:      systemctl status ${MGMT_SERVICE} ${APP_API_SERVICE}"
echo "  Mgmt logs:   journalctl -u ${MGMT_SERVICE} -f"
echo "  API logs:    journalctl -u ${APP_API_SERVICE} -f"
echo ""
