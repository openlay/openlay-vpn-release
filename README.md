# OpenLay VPN — Release Packages

Server deployment packages for OpenLay VPN infrastructure.

## Quick Start

```bash
curl -fsSL -o olv.sh https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh
chmod +x olv.sh
sudo ./olv.sh install olv-management
```

## Packages

| Package | Description |
|---------|-------------|
| `olv-management` | Management server + App API + Admin dashboard |
| `olv-agent` | WireGuard agent (Docker) |

## Usage

### Install

```bash
# Management server (interactive setup)
sudo ./olv.sh install olv-management

# WireGuard agent
sudo ./olv.sh install olv-agent
```

### Update

```bash
sudo ./olv.sh update olv-management
sudo ./olv.sh update olv-agent
```

### Uninstall

```bash
sudo ./olv.sh uninstall olv-management
sudo ./olv.sh uninstall olv-agent
```

## Manual Setup

If you prefer to run the scripts directly:

```bash
git clone https://github.com/openlay/openlay-vpn-release.git
cd openlay-vpn-release

# Management server
cd olv-management/linux
sudo ./install.sh

# Agent
cd agent-setup
sudo ./install.sh
```

## Requirements

- Rocky Linux 8/9, RHEL 8/9, or Ubuntu 20.04+
- Root access
- Internet connection

The installer automatically installs all dependencies (Node.js, PostgreSQL, OpenSSL, Docker).

## Architecture

```
Management Server (port 3084)
├── Admin dashboard (React)
├── REST API for administration
└── WebSocket hub for agent connections

App API (port 443)
├── VPN client API (iOS/macOS/Windows)
├── Device registration & attestation
└── Proxies agent operations via Management

Agent (Docker, per VPN server)
├── WireGuard interface management
├── Firewall & DNS filtering
└── Connects to Management via WebSocket
```
