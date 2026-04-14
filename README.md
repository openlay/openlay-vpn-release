# OpenLay VPN — Release Packages

Server deployment packages for OpenLay VPN infrastructure.

## Architecture

```
┌──────────────────────────────────┐       ┌──────────────────────────┐
│  Management Server               │       │  VPN Agent (Docker)      │
│  ┌────────────────────────────┐  │  WSS  │  ┌────────────────────┐  │
│  │ Admin Dashboard (port 3084)│◄─┼───────┼──│ WireGuard          │  │
│  │ REST API                   │  │       │  │ Firewall            │  │
│  │ WebSocket Agent Hub        │  │       │  │ DNS Filter          │  │
│  ├────────────────────────────┤  │       │  └────────────────────┘  │
│  │ App API (port 443)         │  │       │  Runs on each VPN server │
│  │ VPN client endpoint        │  │       └──────────────────────────┘
│  └────────────────────────────┘  │
│  Install on: 1 management server │
└──────────────────────────────────┘
```

These are **separate packages** installed on **different servers**:
- **olv-management** — Install once on your management server
- **olv-agent** — Install on each VPN server

---

## 1. Management Server

The management server runs the admin dashboard, REST API, and VPN client API.

### Quick Install

```bash
curl -fsSL -o olv.sh https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh
chmod +x olv.sh
sudo ./olv.sh install olv-management
```

The installer will prompt for:
- Domain name
- Database name (default: `olv_management`)
- PostgreSQL URL
- JWT secret (auto-generated if blank)

### What Gets Installed

| Service | Port | Description |
|---------|------|-------------|
| `olv-management` | 3084 | Admin dashboard + API + WebSocket hub |
| `olv-app-api` | 443 | VPN client API (iOS/macOS/Windows) |

Auto-installs: Node.js 20, PostgreSQL, OpenSSL, TLS certs, systemd services.

### Management Commands

```bash
# Update
sudo ./olv.sh update olv-management

# Uninstall
sudo ./olv.sh uninstall olv-management

# Check status
sudo systemctl status olv-management olv-app-api

# View logs
sudo journalctl -u olv-management -f
sudo journalctl -u olv-app-api -f
```

### More Info

See [olv-management/linux/README.md](olv-management/linux/README.md) for detailed documentation.

---

## 2. VPN Agent (Docker)

The agent runs on each VPN server and manages WireGuard tunnels, firewall rules, and DNS filtering.

### Quick Install

```bash
curl -fsSL -o olv.sh https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh
chmod +x olv.sh
sudo ./olv.sh install olv-agent
```

The installer will prompt for:
- Management server URL (default: `https://localhost:3084`)
- Enrollment token (from management dashboard → Settings → Enrollment Tokens)
- VPN listen port (default: `51820`)

### What Gets Installed

| Component | Description |
|-----------|-------------|
| Docker container `olv-agent` | WireGuard + firewall + DNS filter |
| Port `51820/udp` | VPN traffic |

Auto-installs: Docker, Docker Compose, enables IP forwarding.

### Agent Commands

```bash
# Update
sudo ./olv.sh update olv-agent

# Uninstall
sudo ./olv.sh uninstall olv-agent

# View logs
cd /opt/olv-agent && docker compose logs -f

# Restart
cd /opt/olv-agent && docker compose restart
```

---

## Manual Setup

If you prefer to run scripts directly without `olv.sh`:

```bash
git clone https://github.com/openlay/openlay-vpn-release.git
cd openlay-vpn-release

# Management server
cd olv-management/linux
sudo ./install.sh

# Agent (on a different server)
cd olv-agent-dkr
sudo ./install.sh
```

## Requirements

| Package | OS | Dependencies |
|---------|-----|-------------|
| olv-management | Rocky 8/9, RHEL 8/9, Ubuntu 20.04+ | Node.js, PostgreSQL (auto-installed) |
| olv-agent | Any Linux with Docker support | Docker (auto-installed) |

Both require root access and internet connection.
