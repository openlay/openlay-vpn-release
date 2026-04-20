#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────
# OpenLay VPN Agent — Docker One-Line Installer
#
# Usage:
#   curl -sSL <url>/install.sh | bash -s -- \
#     -REPO=git@github.com:org/olv-agent-dkr.git \
#     -MANAGEMENT_URL=https://mngs.livevpn.com:3084/api \
#     -ENROLLMENT_TOKEN=xxx \
#     -SSH_KEY=/path/to/deploy_key
#
# Or with all defaults:
#   ./install.sh -REPO=... -ENROLLMENT_TOKEN=...
# ─────────────────────────────────────────────────────────────

APP_DIR="/opt/olv-agent"
BRANCH="stable"

# Parse KEY=VALUE arguments
for arg in "$@"; do
    case "$arg" in
        -REPO=*) REPO="${arg#*=}" ;;
        -BRANCH=*) BRANCH="${arg#*=}" ;;
        -MANAGEMENT_URL=*) MANAGEMENT_URL="${arg#*=}" ;;
        -ENROLLMENT_TOKEN=*) ENROLLMENT_TOKEN="${arg#*=}" ;;
        -SSH_KEY=*) SSH_KEY="${arg#*=}" ;;
        -APP_DIR=*) APP_DIR="${arg#*=}" ;;
    esac
done

if [ -z "$REPO" ]; then
    echo "ERROR: -REPO is required"
    echo "Usage: ./install.sh -REPO=git@github.com:org/repo.git -ENROLLMENT_TOKEN=xxx"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  OpenLay VPN Agent — Docker Installer"
echo "═══════════════════════════════════════════════════════"
echo "  Repo:       $REPO"
echo "  Branch:     $BRANCH"
echo "  App dir:    $APP_DIR"
echo "  Management: ${MANAGEMENT_URL:-https://mngs.livevpn.com:3084/api}"
echo "═══════════════════════════════════════════════════════"

# ── 1. Install Docker ──────────────────────────────────────

if ! command -v docker &>/dev/null; then
    echo "[1/7] Installing Docker..."
    if command -v dnf &>/dev/null; then
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif command -v apt-get &>/dev/null; then
        curl -fsSL https://get.docker.com | sh
    elif command -v apk &>/dev/null; then
        apk add docker docker-compose
    else
        echo "ERROR: Unsupported package manager. Install Docker manually."
        exit 1
    fi
    systemctl enable --now docker
else
    echo "[1/7] Docker already installed: $(docker --version)"
fi

# ── 2. Setup SSH key ───────────────────────────────────────

echo "[2/7] Setting up SSH deploy key..."
mkdir -p "$APP_DIR/.ssh"

if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    cp "$SSH_KEY" "$APP_DIR/.ssh/deploy_key"
elif [ ! -f "$APP_DIR/.ssh/deploy_key" ]; then
    echo "No SSH key provided. Generating new key pair..."
    ssh-keygen -t ed25519 -f "$APP_DIR/.ssh/deploy_key" -N "" -C "olv-agent-deploy"
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║  Add this deploy key to your git repo:          ║"
    echo "╚══════════════════════════════════════════════════╝"
    cat "$APP_DIR/.ssh/deploy_key.pub"
    echo ""
    read -p "Press Enter after adding the key to continue..." _
fi
chmod 600 "$APP_DIR/.ssh/deploy_key"

export GIT_SSH_COMMAND="ssh -i $APP_DIR/.ssh/deploy_key -o StrictHostKeyChecking=no"

# ── 3. Clone repo ──────────────────────────────────────────

if [ -d "$APP_DIR/.git" ]; then
    echo "[3/7] Repo exists, pulling latest..."
    cd "$APP_DIR"
    git fetch origin "$BRANCH"
    git reset --hard "origin/$BRANCH"
else
    echo "[3/7] Cloning repo..."
    git clone -b "$BRANCH" "$REPO" "$APP_DIR"
    cd "$APP_DIR"
fi

# ── 4. Create .env ─────────────────────────────────────────

echo "[4/7] Configuring .env..."
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    if [ -n "$MANAGEMENT_URL" ]; then
        sed -i "s|^MANAGEMENT_API_URL=.*|MANAGEMENT_API_URL=$MANAGEMENT_URL|" "$APP_DIR/.env"
    fi
    if [ -n "$ENROLLMENT_TOKEN" ]; then
        sed -i "s|^ENROLLMENT_TOKEN=.*|ENROLLMENT_TOKEN=$ENROLLMENT_TOKEN|" "$APP_DIR/.env"
    fi
    echo "  .env created"
else
    echo "  .env already exists, skipping"
fi

# ── 5. Enable ip_forward ──────────────────────────────────

echo "[5/7] Enabling ip_forward..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.d/99-wireguard.conf 2>/dev/null; then
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf
fi

# ── 5b. firewalld: allow VPN traffic ──────────────────────
# On distros that run firewalld (RHEL/Rocky), the default filter_FORWARD chain
# ends with "reject with admin-prohibited". VPN peer-to-peer packets go through
# this chain and get dropped unless the VPN subnets/interfaces are trusted.

if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
    echo "  Configuring firewalld (WG ports + trusted VPN subnets)..."
    firewall-cmd --permanent --add-port=51820-51830/udp >/dev/null 2>&1 || true
    # Trust common VPN subnets so peer-to-peer and peer-to-LAN forwarding passes
    # firewalld's filter_FORWARD chain. Trusting sources rather than interfaces
    # avoids having to re-register each new wg/olv iface the agent creates.
    for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        firewall-cmd --permanent --zone=trusted --add-source=$cidr >/dev/null 2>&1 || true
    done
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# ── 6. Build & Start ──────────────────────────────────────

echo "[6/7] Building and starting Docker container..."
cd "$APP_DIR"
docker compose build
docker compose up -d

# Wait for agent to connect
echo "  Waiting for agent to start..."
sleep 5
if docker ps --format '{{.Names}}' | grep -q olv-agent; then
    echo "  Container running"
else
    echo "  WARNING: Container may not be running. Check: docker logs olv-agent"
fi

# ── 7. Install auto-update timer ──────────────────────────

echo "[7/7] Installing auto-update timer (every 5 min)..."
chmod +x "$APP_DIR/setup/auto-update.sh"
cp "$APP_DIR/setup/olv-auto-update.service" /etc/systemd/system/
cp "$APP_DIR/setup/olv-auto-update.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now olv-auto-update.timer

# ── Done ──────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Installation complete!"
echo "═══════════════════════════════════════════════════════"
echo "  App dir:     $APP_DIR"
echo "  Container:   docker logs olv-agent"
echo "  Auto-update: systemctl list-timers | grep olv"
echo "  Config:      $APP_DIR/.env"
echo ""
echo "  Firewall: open UDP ports 51820-51830"
if command -v firewall-cmd &>/dev/null; then
    echo "    firewall-cmd --permanent --add-port=51820-51830/udp && firewall-cmd --reload"
elif command -v ufw &>/dev/null; then
    echo "    ufw allow 51820:51830/udp"
fi
echo "═══════════════════════════════════════════════════════"
