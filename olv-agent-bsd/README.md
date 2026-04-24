# OpenLay VPN Agent (FreeBSD)

Static Go binary port of the VPN agent. Runs on **FreeBSD 13.2+** with
kernel `if_wg` + pf. One binary, no runtime dependencies beyond
`wireguard-tools` (for `wg` / `wg-quick`) and `pfctl` (in base).

## Install

```sh
cd /tmp
fetch https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh
chmod +x install.sh
./install.sh
```

The installer:
1. Loads `if_wg` kernel module + bumps `net.fibs` for policy routing
2. `pkg install wireguard-tools ca_root_nss`
3. Enables pf + IP forwarding + adds `olv-nat/*`, `olv-policy/*`,
   `olv-fw/*`, `olv-rdr/*` anchors to `/etc/pf.conf`
4. Copies the right binary for your arch to `/usr/local/sbin/olv-agent`
5. Installs rc.d service + sample `agent.conf`
6. Starts the service

After install, edit `/usr/local/etc/olv-agent/agent.conf` to fill in
`MANAGEMENT_API_URL` and `ENROLLMENT_TOKEN`, then:

```sh
service olv-agent restart
tail -f /var/log/olv-agent.log
```

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
