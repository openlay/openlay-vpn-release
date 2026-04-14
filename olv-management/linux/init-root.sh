#!/bin/bash
# =============================================================================
# OpenLay VPN Management — Create Root Admin Account
# Run as root: ./init-root.sh
#
# Creates a root admin user that can manage all enterprises.
# =============================================================================
set -e

SERVICE_USER="olv-management"
HOME_DIR="/home/${SERVICE_USER}"
MGMT_DIR="${HOME_DIR}/wireguard-management"

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

ask_password() {
  local var_name="$1" prompt="$2"
  local current="${!var_name}"
  if [ -n "$current" ]; then return; fi
  while true; do
    read -srp "$(echo -e "${CYAN}?${NC}") ${prompt}: " pass1 < /dev/tty; echo
    if [ -z "$pass1" ]; then
      warn "  Password cannot be empty."; continue
    fi
    read -srp "$(echo -e "${CYAN}?${NC}") Confirm password: " pass2 < /dev/tty; echo
    if [ "$pass1" != "$pass2" ]; then
      warn "  Passwords do not match. Try again."; continue
    fi
    eval "$var_name=\"$pass1\""
    break
  done
}

if [ "$EUID" -ne 0 ]; then error "This script must be run as root"; fi
if [ ! -d "$MGMT_DIR" ]; then error "Management server not installed. Run install.sh first."; fi

echo ""
echo "==========================================="
echo -e "${GREEN}  Create Root Admin Account${NC}"
echo "==========================================="
echo ""

ask ROOT_USERNAME "Username" "admin"
ask ROOT_EMAIL    "Email" ""
ask ROOT_NAME     "Display name" "$ROOT_USERNAME"
ask_password ROOT_PASSWORD "Password"

# Read DB_URL from .env
DB_URL=$(grep "^DATABASE_URL=" "$MGMT_DIR/.env" 2>/dev/null | cut -d'=' -f2-)
if [ -z "$DB_URL" ]; then
  DB_NAME=$(grep "^DB_NAME=" "$MGMT_DIR/.env" 2>/dev/null | cut -d'=' -f2-)
  DB_NAME="${DB_NAME:-olv_management}"
  DB_URL="postgres://${SERVICE_USER}@127.0.0.1:5432/${DB_NAME}"
fi

info "Hashing password..."

# Hash password using Node.js (scrypt, same as server auth.js)
PASSWORD_HASH=$(node -e "
const crypto = require('crypto');
const salt = crypto.randomBytes(16).toString('hex');
crypto.scrypt(process.argv[1], salt, 64, (err, key) => {
  if (err) { console.error(err); process.exit(1); }
  console.log(salt + ':' + key.toString('hex'));
});
" "$ROOT_PASSWORD" 2>&1)

if [ -z "$PASSWORD_HASH" ] || [[ "$PASSWORD_HASH" == *"Error"* ]]; then
  error "Failed to hash password. Is Node.js installed?"
fi

info "Creating user..."

# Create user + set as root (all in one transaction)
cd /tmp
sudo -u "$SERVICE_USER" psql "$DB_URL" << SQL
BEGIN;

-- Create user (skip if username already exists)
INSERT INTO users (id, username, email, name, password_hash, auth_type, status)
VALUES (
  gen_random_uuid()::text,
  '${ROOT_USERNAME}',
  '${ROOT_EMAIL}',
  '${ROOT_NAME}',
  '${PASSWORD_HASH}',
  'password',
  'enabled'
)
ON CONFLICT (username) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  name = EXCLUDED.name,
  email = EXCLUDED.email,
  updated_at = NOW();

-- Add to root_users
INSERT INTO root_users (user_id)
SELECT id FROM users WHERE username = '${ROOT_USERNAME}'
ON CONFLICT DO NOTHING;

COMMIT;
SQL

if [ $? -eq 0 ]; then
  echo ""
  echo "==========================================="
  echo -e "${GREEN}Root account created!${NC}"
  echo "==========================================="
  echo ""
  echo "  Username: ${ROOT_USERNAME}"
  echo "  Email:    ${ROOT_EMAIL}"
  echo "  Role:     root (system-wide)"
  echo ""
  echo "  Login via iOS management app or web dashboard."
  echo "  After login, create your first enterprise."
  echo ""
else
  error "Failed to create root account. Check database connection."
fi
