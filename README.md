# OpenLay VPN — Release Packages

Server deployment packages for OpenLay VPN infrastructure.

## Architecture

```
┌──────────────────────────────────┐       ┌──────────────────────────────┐
│  Management Server (Linux)       │       │  VPN Agent (FreeBSD)         │
│  ┌────────────────────────────┐  │  WSS  │  ┌────────────────────────┐  │
│  │ Admin API (port 3084)      │◄─┼───────┼──│ WireGuard (if_wg)      │  │
│  │ REST API                   │  │       │  │ Firewall (pf)          │  │
│  │ WebSocket Agent Hub        │  │       │  │ DNS Filter             │  │
│  ├────────────────────────────┤  │       │  └────────────────────────┘  │
│  │ App API (port 443)         │  │       │  Native Go binary, rc.d      │
│  │ VPN client endpoint        │  │       │  Runs on each VPN server     │
│  └────────────────────────────┘  │       └──────────────────────────────┘
│  Install on: 1 management server │
└──────────────────────────────────┘
```

These are **separate packages** installed on **different servers**:
- **olv-management** — Install once on your management server (Linux)
- **olv-agent-bsd** — Native FreeBSD agent on each VPN server (static Go binary, uses `if_wg` + pf)

> **Note:** The Linux Docker agent (`olv-agent-dkr`) is no longer supported. New deployments should use `olv-agent-bsd` on FreeBSD.

---

## 1. Management Server

The management server runs the admin REST API + WebSocket agent hub and the VPN client API. All admin actions are driven from the OpenLay iOS app.

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

### Install the Admin App

All admin actions happen in the **OpenLay iOS app** — there is no web UI.

> [Join the TestFlight beta](https://testflight.apple.com/join/nSmM9h5d)

### Create the First Root Admin

There are two ways to create the first root account:

**A. QR + Apple Sign-In (default)** — `install.sh` finishes by printing a
one-shot QR code and a `ROOT_SETUP_TOKEN`. Open the iOS app → tap **Scan
Setup QR** on the login screen → scan the QR → sign in with Apple. The
server upserts the user and grants root. Once a root exists the bootstrap
endpoint becomes inert (HTTP 410), so this can only be used once.

If you missed the QR, re-print the token from the server:

```bash
sudo grep ROOT_SETUP_TOKEN /home/olv-management/wireguard-management/.env
```

**B. Password-based (`init-root.sh`)** — for environments where Apple
Sign-In isn't usable, or to add additional root accounts later:

```bash
sudo ./olv.sh init-root olv-management
```

Prompts for username, email, password and creates the root row directly
in Postgres.

### Reset the Root Password (lost device or forgotten password)

Re-run `init-root.sh` with the same username — `password_hash` is
overwritten and **all active sessions for that user are revoked in the
same transaction**, so any prior device holding an access JWT is logged
out on its next request:

```bash
sudo ./olv.sh init-root olv-management
# enter the existing username, then a new password
```

The lost device must scan the QR / log in again with the new password.

### What Gets Installed

| Service | Port | Description |
|---------|------|-------------|
| `olv-management` | 3084 | Admin API + WebSocket agent hub |
| `olv-app-api` | 443 | VPN client API (iOS/macOS/Windows) |

Auto-installs: Node.js 20, PostgreSQL, OpenSSL, TLS certs, systemd services.

### Management Commands

```bash
# Create root admin
sudo ./olv.sh init-root olv-management

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

## 2. VPN Agent (FreeBSD)

Static Go binary for **FreeBSD 14.4-RELEASE** (amd64 / arm64) using kernel `if_wg` + pf. No Docker, no Node runtime — one binary under `/usr/local/sbin/olv-agent` managed by rc.d.

### Quick Install

Run as **root** (FreeBSD base has no `sudo`; use `su -` or log in as root):

```sh
fetch -qo - https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh | sh
```

Non-interactive (CI / automation):

```sh
MANAGEMENT_API_URL=https://mng.livevpn.com:3084 \
ENROLLMENT_TOKEN=your-one-time-token \
  sh -c "$(fetch -qo - https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh)"
```

Or via `olv.sh` after cloning the repo (auto-dispatches to the FreeBSD agent):

```sh
fetch -qo olv.sh https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv.sh
chmod +x olv.sh
./olv.sh install olv-agent
```

Get an enrollment token from the OpenLay iOS management app → Settings → Enrollment Tokens.

### What Gets Installed

| Component | Description |
|-----------|-------------|
| `/usr/local/sbin/olv-agent` | Static Go binary (amd64 or arm64) |
| `/usr/local/etc/rc.d/olv-agent` | rc.d service |
| `/usr/local/etc/olv-agent/agent.conf` | URL + token config |
| `/var/db/olv-agent/certs/` | Client cert issued by management |
| pf anchors | `olv-rdr/*`, `olv-nat/*`, `olv-policy/*`, `olv-fw/*` in `/etc/pf.conf` |
| Port `51820/udp` | VPN traffic |

Auto-installs: `wireguard-tools`, `ca_root_nss` via `pkg`. Loads `if_wg` kernel module, enables pf + IP forwarding. Binary sha256-verified against `SHA256SUMS`.

### Agent Commands

Run as **root** (FreeBSD base has no `sudo`).

```sh
# Status / restart / stop
service olv-agent status
service olv-agent restart
service olv-agent stop

# Logs (rc.d stdout/stderr)
tail -f /var/log/olv-agent.log

# Update (idempotent — preserves agent.conf + certs)
./olv.sh update olv-agent

# Uninstall
./olv.sh uninstall olv-agent
```

See [olv-agent-bsd/README.md](olv-agent-bsd/README.md) for pf layout, cert rotation, and troubleshooting.

---

## Manual Setup

If you prefer to run scripts directly without the one-liner installers:

Management server (Linux, use `sudo`):

```bash
git clone https://github.com/openlay/openlay-vpn-release.git
cd openlay-vpn-release/olv-management/linux
sudo ./install.sh
```

Agent (FreeBSD VPN server, run as root — no `sudo`):

```sh
git clone https://github.com/openlay/openlay-vpn-release.git
cd openlay-vpn-release/olv-agent-bsd
sh ./install.sh
```

## Requirements

| Package | OS | Dependencies |
|---------|-----|-------------|
| olv-management | Rocky 8/9, RHEL 8/9, Ubuntu 20.04+ | Node.js, PostgreSQL (auto-installed) |
| olv-agent-bsd | FreeBSD 14.4-RELEASE (amd64 / arm64) | `wireguard-tools`, `ca_root_nss` (auto via `pkg`), kernel `if_wg`, pf |

All require root access and internet connection. FreeBSD base has no `sudo` — run the agent installer as root directly.
