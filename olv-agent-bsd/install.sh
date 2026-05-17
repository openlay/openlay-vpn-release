#!/bin/sh
# OpenLay VPN agent installer for FreeBSD 13.2+.
# Run as root. Idempotent — safe to re-run after an upgrade.
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "must be run as root" >&2
	exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="${BIN_SRC:-$HERE/../../bin/olv-agent-freebsd-amd64}"

if [ ! -x "$BIN_SRC" ]; then
	echo "binary not found at $BIN_SRC — run 'make freebsd' first" >&2
	exit 1
fi

echo "[1/6] ensuring kernel wg module + multi-FIB support"
kldstat -q -m if_wg || kldload if_wg
grep -q '^if_wg_load=' /boot/loader.conf || echo 'if_wg_load="YES"' >> /boot/loader.conf
# Policy-based routing (M2) needs multiple FIBs. net.fibs is a boot-time
# tunable — set it now in loader.conf and warn the operator to reboot
# if the live value differs from the target. We default to 4 (0=main,
# 1..3 available for policies). Admins can raise it by hand if they
# need more — this script only sets the value when unset.
OLV_TARGET_FIBS="${OLV_TARGET_FIBS:-4}"
if ! grep -q '^net.fibs=' /boot/loader.conf; then
	echo "net.fibs=\"${OLV_TARGET_FIBS}\"" >> /boot/loader.conf
	echo "  wrote net.fibs=${OLV_TARGET_FIBS} to /boot/loader.conf"
fi
RUNNING_FIBS="$(sysctl -n net.fibs 2>/dev/null || echo 1)"
if [ "$RUNNING_FIBS" != "$OLV_TARGET_FIBS" ]; then
	echo "  WARN: running net.fibs=$RUNNING_FIBS, loader.conf wants $OLV_TARGET_FIBS — REBOOT to activate policy routing"
fi

echo "[2/6] installing package deps"
# pf is in base. wireguard-tools for wg/wg-quick userspace, ca_root_nss for
# TLS when talking to cloud metadata + management server.
pkg install -y wireguard-tools ca_root_nss >/dev/null

echo "[3/6] enabling pf, ip forwarding, and wiring anchors"
sysrc pf_enable=YES >/dev/null
sysrc pflog_enable=YES >/dev/null
# Gateway mode — VPN only works if the host forwards between bsd0 and the
# WAN iface. Set both the live knob and /etc/sysctl.conf so it survives
# reboot.
sysctl net.inet.ip.forwarding=1 >/dev/null
grep -q '^net.inet.ip.forwarding' /etc/sysctl.conf || echo 'net.inet.ip.forwarding=1' >> /etc/sysctl.conf
sysrc gateway_enable=YES >/dev/null
if ! grep -q '# --- OpenLay VPN agent anchors' /etc/pf.conf 2>/dev/null; then
	# Anchor ordering is load-bearing — pf evaluates top-down:
	#   rdr-anchor  (M3) : DNAT rewrites destination BEFORE filter sees it
	#   nat-anchor  (M3) : SNAT rewrites source AFTER filter decides
	#   olv-policy  (M2) : policy-based routing (route-to). Runs before
	#                      olv-fw so it can override block_wan/block_all.
	#   olv-fw      (M1) : filter rules + default policy (terminal).
	cat >> /etc/pf.conf <<-EOF

	# --- OpenLay VPN agent anchors (do not edit by hand — agent owns these) ---
	# DNAT / port-forward (M3). rdr-anchor MUST appear before filter anchors.
	rdr-anchor "olv-rdr/*"
	# NAT so VPN peers can reach the internet through the WAN iface.
	nat-anchor "olv-nat/*"
	# Policy-based routing (M2). route-to rules may shadow the filter
	# anchor below — this is the opt-in override layer.
	anchor "olv-policy/*"
	# Per-interface filter rules (system + user rules + policy).
	anchor "olv-fw/*"
	EOF
elif ! grep -q 'olv-policy/' /etc/pf.conf 2>/dev/null; then
	# M1-era /etc/pf.conf — inject the new anchors just above olv-fw.
	echo "  extending existing anchor block with olv-rdr + olv-policy"
	sed -i '' '/anchor "olv-fw/i\
rdr-anchor "olv-rdr/*"\
anchor "olv-policy/*"\
' /etc/pf.conf
fi
# Reload only if pf is running; otherwise start it. Either way leaves a
# sane state.
if pfctl -s info >/dev/null 2>&1; then
	pfctl -f /etc/pf.conf
else
	service pf start || true
fi

echo "[4/6] installing binary + rc.d service"
install -m 0755 "$BIN_SRC" /usr/local/sbin/olv-agent
install -d -m 0755 /usr/local/etc/olv-agent
install -d -m 0755 /usr/local/etc/wireguard
install -d -m 0700 /var/db/olv-agent/certs

if [ ! -f /usr/local/etc/olv-agent/agent.conf ]; then
	install -m 0600 "$HERE/agent.conf.sample" /usr/local/etc/olv-agent/agent.conf
	echo "  wrote /usr/local/etc/olv-agent/agent.conf (edit it now!)"
fi

install -m 0755 "$HERE/olv-agent.rc" /usr/local/etc/rc.d/olv-agent

echo "[5/6] enabling + starting service"
sysrc olv_agent_enable=YES >/dev/null
service olv-agent restart || service olv-agent start

# `service olv-agent restart` returning success does NOT guarantee the
# daemon stayed alive. The rc.d script can return before the forked
# daemon dies (port 53 collision with the still-shutting-down old
# process, stale pidfile race, immediate exit on config error, etc.).
# Verify daemon is actually alive 5s later, surface log on failure.
echo "  verifying daemon is alive..."
sleep 5
PIDFILE=/var/run/olv_agent.pid
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
	echo "  daemon alive (pid $(cat "$PIDFILE"))"
else
	echo "  ERROR: daemon failed to stay running after restart" >&2
	echo "  ---- /var/log/olv-agent.log (last 30 lines) ----" >&2
	tail -30 /var/log/olv-agent.log 2>/dev/null >&2 || echo "  (log file not readable)" >&2
	exit 1
fi

echo "[6/6] done."
echo
echo "Edit /usr/local/etc/olv-agent/agent.conf, then: service olv-agent restart"
echo "Logs: tail -f /var/log/olv-agent.log"
