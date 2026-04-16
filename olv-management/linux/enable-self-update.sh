#!/bin/bash
# =============================================================================
# Enable self-update capability for existing installations.
# Run ONCE as root to grant the service user permission to run update.sh
# via sudo (for triggering updates from the iOS management app).
# =============================================================================
set -e

SERVICE_USER="olv-management"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then error "This script must be run as root"; fi

if ! id "$SERVICE_USER" &>/dev/null; then
  error "User '${SERVICE_USER}' does not exist. Run install.sh first."
fi

cat > "/etc/sudoers.d/${SERVICE_USER}" << SUDOEOF
${SERVICE_USER} ALL=(ALL) NOPASSWD: /bin/bash /opt/openlay-vpn-release/olv-management/linux/update.sh
${SERVICE_USER} ALL=(ALL) NOPASSWD: /usr/bin/git -C /opt/openlay-vpn-release pull
${SERVICE_USER} ALL=(ALL) NOPASSWD: /usr/bin/git -C /opt/openlay-vpn-release fetch
SUDOEOF
chmod 440 "/etc/sudoers.d/${SERVICE_USER}"

info "Self-update enabled. '${SERVICE_USER}' can now run update.sh via sudo."
info "You can now trigger updates from the iOS management app."
