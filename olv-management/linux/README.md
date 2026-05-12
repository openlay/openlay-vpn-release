# OpenLay VPN Management Server — Linux

## Quick Install

```bash
# Download
git clone https://github.com/openlay/openlay-vpn-release.git
cd openlay-vpn-release/olv-management/linux

# Install (run as root)
sudo ./install.sh
```

The installer will ask for configuration:

```
? Domain name (e.g. mng.livevpn.com): mng.example.com
? Database name [wireguard_management]: 
? PostgreSQL URL [postgres://olv-management@127.0.0.1:5432/wireguard_management]: 
? JWT secret (leave blank to auto-generate): 
? Apple Team ID (leave blank to skip): 
? Apple Client IDs [com.openlay.management]: 
```

Press Enter to accept defaults. The installer handles everything automatically:
- Node.js 20.x
- PostgreSQL (install, init, create database)
- TLS certificates (self-signed)
- Systemd services
- Firewall rules
- SELinux policies (Rocky/RHEL)

## What Gets Installed

| Service | Port | Description |
|---------|------|-------------|
| `olv-management` | 3084 | Admin API + WebSocket agent hub |
| `olv-app-api` | 443 | VPN client API (iOS/macOS/Windows) |

Both services share one PostgreSQL database and run under the `olv-management` user.

## After Install

```bash
# Check status
sudo systemctl status olv-management olv-app-api

# View logs
sudo journalctl -u olv-management -f
sudo journalctl -u olv-app-api -f
```

All admin actions happen from the OpenLay iOS app — [join the
TestFlight beta](https://testflight.apple.com/join/nSmM9h5d). The
install script ends by printing a one-shot QR; scan it from the app to
enroll the first root user.

## Update

```bash
cd openlay-vpn-release
git pull
cd olv-management/linux
sudo ./update.sh
```

This will:
1. Stop both services
2. Backup current installation
3. Copy new files (preserves `.env` and certificates)
4. Reinstall dependencies
5. Restart services

## Uninstall

```bash
sudo ./uninstall.sh
```

Options:
- `--force` — remove everything without prompting
- `--keep-db` — keep the database
- `--keep-user` — keep the service user

## Configuration

Config files are created during install and preserved during updates:

- `/home/olv-management/wireguard-management/.env` — Management server
- `/home/olv-management/app-api/.env` — App API

To edit after install:

```bash
sudo -u olv-management nano /home/olv-management/wireguard-management/.env
sudo systemctl restart olv-management

sudo -u olv-management nano /home/olv-management/app-api/.env
sudo systemctl restart olv-app-api
```

## Requirements

- Rocky Linux 8/9, RHEL 8/9, or Ubuntu 20.04+
- Root access
- Internet connection (for installing Node.js and PostgreSQL)
- Ports 443 and 3084 available

## File Structure

```
/home/olv-management/
├── wireguard-management/
│   ├── server/          # Management API + WebSocket agent hub
│   ├── certs/           # TLS certificates
│   └── .env             # Configuration (includes ROOT_SETUP_TOKEN)
└── app-api/
    ├── src/             # VPN client API
    ├── certs/           # TLS certificates
    └── .env             # Configuration
```
