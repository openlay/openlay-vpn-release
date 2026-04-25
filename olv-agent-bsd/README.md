# OpenLay VPN Agent (FreeBSD)

Static Go binary port of the VPN agent. Runs on **FreeBSD 14.4-RELEASE**
(amd64 / arm64) with kernel `if_wg` + pf. One binary, no runtime
dependencies beyond `wireguard-tools` (for `wg` / `wg-quick`) and
`pfctl` (in base).

## Install

### Fastest — one-liner (interactive)

```sh
fetch -qo - https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh | sh
```

The installer prompts for **Management URL** + **Enrollment token**,
downloads the right binary for your arch, verifies sha256, wires up pf
anchors + IP forwarding, and starts the service. Agent is online when
the script exits.

### Non-interactive (automation)

```sh
MANAGEMENT_API_URL=https://mng.livevpn.com:3084 \
ENROLLMENT_TOKEN=your-one-time-token \
  sh -c "$(fetch -qo - https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh)"
```

### What the installer does

1. Loads `if_wg` kernel module + bumps `net.fibs` for policy routing
2. `pkg install wireguard-tools ca_root_nss`
3. Enables pf + IP forwarding + adds `olv-rdr/*`, `olv-nat/*`,
   `olv-policy/*`, `olv-fw/*` anchors to `/etc/pf.conf`
4. Installs `/usr/local/sbin/olv-agent` (arch-correct binary, sha256-verified)
5. Installs rc.d service + writes `/usr/local/etc/olv-agent/agent.conf`
   with the URL + token you provided
6. Starts the service

Re-running the installer on the same host is safe — agent.conf + cert
dir are preserved.

## Layout

```
olv-agent-bsd/
├── install.sh           One-shot installer
├── uninstall.sh         Reverse of install
├── olv-agent.rc         /usr/local/etc/rc.d/olv-agent
├── agent.conf.sample    Config template
├── pf.conf.snippet      /etc/pf.conf anchor declarations (docs)
├── VERSION              Current release version
├── SHA256SUMS            Binary checksums
└── bin/
    ├── olv-agent-freebsd-amd64
    └── olv-agent-freebsd-arm64
```

Installer picks the binary by `uname -m`. Override via `BIN_SRC=/path ./install.sh`.

## Uninstall

```sh
./uninstall.sh
```

Stops service, removes `/usr/local/sbin/olv-agent` + rc.d script. Leaves
config + cert dir in place (`/usr/local/etc/olv-agent/`, `/var/db/olv-agent/`)
so reinstall keeps the agent identity.

## Verify

```sh
/usr/local/sbin/olv-agent -version      # prints baked-in version
shasum -a 256 -c SHA256SUMS              # verify binary integrity
```

## Source

- Agent source: <https://github.com/openlay/olv-agent-bsd>
- Release channel: <https://github.com/openlay/openlay-vpn-release/tree/main/olv-agent-bsd>
