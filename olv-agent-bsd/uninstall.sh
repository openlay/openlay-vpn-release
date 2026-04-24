#!/bin/sh
# Remove OpenLay VPN agent from a FreeBSD host. Keeps rule JSON +
# WireGuard configs + cert dir by default so a reinstall picks up where
# it left off. Pass --purge to drop them too.
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "must be run as root" >&2
	exit 1
fi

PURGE=0
case "${1:-}" in
	--purge) PURGE=1 ;;
esac

echo "[1/4] stopping service"
service olv-agent stop 2>/dev/null || true
sysrc -x olv_agent_enable 2>/dev/null || true

echo "[2/4] removing rc.d + binary"
rm -f /usr/local/etc/rc.d/olv-agent
rm -f /usr/local/sbin/olv-agent

echo "[3/4] clearing pf anchor (root declaration in /etc/pf.conf stays)"
pfctl -a 'olv-fw' -F rules 2>/dev/null || true

if [ "$PURGE" -eq 1 ]; then
	echo "[4/4] purging config + data"
	rm -rf /usr/local/etc/olv-agent
	rm -rf /var/db/olv-agent
	rm -f /usr/local/etc/wireguard/*-firewall.json
	rm -f /usr/local/etc/wireguard/*-dns-blocklist.json
	rm -f /usr/local/etc/wireguard/firewall-policy.json
	rm -f /var/log/olv-agent.log
else
	echo "[4/4] keeping /usr/local/etc/olv-agent and /var/db/olv-agent (pass --purge to remove)"
fi

echo "done."
