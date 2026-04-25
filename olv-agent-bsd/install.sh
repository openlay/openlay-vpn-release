#!/bin/sh
# OpenLay VPN agent installer for FreeBSD 14.4-RELEASE.
# Run as root. Idempotent — safe to re-run after an upgrade.
#
# Three ways to invoke:
#
#   1. One-liner (fetch + run). Downloads everything on demand.
#      fetch https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh \
#        && sh install.sh
#
#   2. From a local release bundle (this directory with bin/ populated).
#        cd olv-agent-bsd && ./install.sh
#
#   3. From the olv-agent-bsd source tree (deploy/freebsd/install.sh, with
#      `make freebsd` having produced ../../bin/olv-agent-freebsd-amd64).
#
# Env overrides:
#   MANAGEMENT_API_URL — mgmt URL; if set, no prompt. Example: https://mng.livevpn.com:3084
#   ENROLLMENT_TOKEN   — one-time token from mgmt; if set, no prompt.
#   BASE_URL   — raw URL prefix for remote fetches (default: GitHub main).
#   BIN_SRC    — explicit path to a pre-built binary; skips arch detection.
#   OLV_TARGET_FIBS — FreeBSD net.fibs boot tunable (default 4).
#
# Fastest install (interactive — prompts URL + token):
#   fetch -o - https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh | sh
#
# Or non-interactive:
#   MANAGEMENT_API_URL=https://mng.livevpn.com:3084 ENROLLMENT_TOKEN=xxx \
#     sh -c "$(fetch -qo - https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd/install.sh)"

set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "must be run as root" >&2
	exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE_URL="${BASE_URL:-https://raw.githubusercontent.com/openlay/openlay-vpn-release/main/olv-agent-bsd}"

ARCH="$(uname -m)"
case "$ARCH" in
	amd64|x86_64) BIN_NAME="olv-agent-freebsd-amd64" ;;
	arm64|aarch64) BIN_NAME="olv-agent-freebsd-arm64" ;;
	*) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# -------------------------------------------------------------------------
# Resolve the working directory that holds bin/ + olv-agent.rc + agent.conf.sample.
#
# Precedence:
#   1. Caller overrode BIN_SRC → use as-is, derive ASSET_DIR from its parent.
#   2. $HERE/bin/<BIN_NAME> exists → release-bundle layout (git clone of the
#      openlay-vpn-release repo).
#   3. $HERE/../../bin/<BIN_NAME> exists → source-tree layout (running
#      deploy/freebsd/install.sh from olv-agent-bsd after `make freebsd`).
#   4. Nothing local → one-liner mode: fetch everything into /tmp from
#      $BASE_URL and verify the binary with SHA256SUMS.
#
# ASSET_DIR is where agent.conf.sample + olv-agent.rc live for step [4/6].
# -------------------------------------------------------------------------

ASSET_DIR="$HERE"
if [ -n "${BIN_SRC:-}" ]; then
	:
elif [ -x "$HERE/bin/$BIN_NAME" ]; then
	BIN_SRC="$HERE/bin/$BIN_NAME"
elif [ -x "$HERE/../../bin/$BIN_NAME" ]; then
	BIN_SRC="$HERE/../../bin/$BIN_NAME"
	# Source tree layout: rc file + conf sample are in deploy/freebsd/ (=HERE).
else
	echo "==> binaries not found locally — fetching from $BASE_URL"
	need_bin() { command -v "$1" >/dev/null || { echo "need $1 in PATH" >&2; exit 1; }; }
	need_bin fetch
	need_bin sha256

	STAGE="$(mktemp -d -t olv-agent-install.XXXXXX)"
	trap 'rm -rf "$STAGE"' EXIT INT TERM
	mkdir -p "$STAGE/bin"

	# The handful of files the installer needs at runtime. README / VERSION
	# are informational and skipped to keep the one-liner quick.
	fetch -q -o "$STAGE/bin/$BIN_NAME" "$BASE_URL/bin/$BIN_NAME"
	fetch -q -o "$STAGE/SHA256SUMS"   "$BASE_URL/SHA256SUMS"
	fetch -q -o "$STAGE/olv-agent.rc" "$BASE_URL/olv-agent.rc"
	fetch -q -o "$STAGE/agent.conf.sample" "$BASE_URL/agent.conf.sample"

	# Verify sha256 — integrity is the entire point of shipping SHA256SUMS.
	echo "==> verifying $BIN_NAME"
	EXPECTED="$(awk -v f="$BIN_NAME" '$2 == f { print $1 }' "$STAGE/SHA256SUMS")"
	if [ -z "$EXPECTED" ]; then
		echo "no checksum for $BIN_NAME in SHA256SUMS" >&2
		exit 1
	fi
	GOT="$(sha256 -q "$STAGE/bin/$BIN_NAME")"
	if [ "$EXPECTED" != "$GOT" ]; then
		echo "sha256 mismatch for $BIN_NAME" >&2
		echo "  expected $EXPECTED" >&2
		echo "  got      $GOT" >&2
		exit 1
	fi

	chmod 755 "$STAGE/bin/$BIN_NAME"
	BIN_SRC="$STAGE/bin/$BIN_NAME"
	ASSET_DIR="$STAGE"
fi

if [ ! -x "$BIN_SRC" ]; then
	echo "binary not executable at $BIN_SRC" >&2
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
	# Collect mgmt URL + enrollment token up front so the agent can come
	# online immediately. Values from env vars win (non-interactive /
	# automated installs); otherwise prompt the operator.
	URL_VAL="${MANAGEMENT_API_URL:-}"
	TOKEN_VAL="${ENROLLMENT_TOKEN:-}"
	if [ -z "$URL_VAL" ] || [ -z "$TOKEN_VAL" ]; then
		# Bind stdin to the terminal in case the script was piped (`fetch |
		# sh`) — otherwise /dev/stdin is the pipe, not the keyboard.
		if [ ! -t 0 ] && [ -e /dev/tty ]; then
			exec </dev/tty
		fi
	fi
	if [ -z "$URL_VAL" ]; then
		printf 'Management URL (e.g. https://mng.livevpn.com:3084): '
		read URL_VAL
	fi
	if [ -z "$TOKEN_VAL" ]; then
		printf 'Enrollment token: '
		read TOKEN_VAL
	fi
	if [ -z "$URL_VAL" ] || [ -z "$TOKEN_VAL" ]; then
		echo "MANAGEMENT_API_URL and ENROLLMENT_TOKEN are both required" >&2
		exit 1
	fi
	install -m 0600 "$ASSET_DIR/agent.conf.sample" /usr/local/etc/olv-agent/agent.conf
	# In-place substitute placeholders. The sample has `replace-me` for the
	# token and the staging URL for MANAGEMENT_API_URL; both get rewritten.
	URL_ESC=$(printf '%s\n' "$URL_VAL" | sed 's#[\\/&]#\\&#g')
	TOKEN_ESC=$(printf '%s\n' "$TOKEN_VAL" | sed 's#[\\/&]#\\&#g')
	sed -i '' \
		-e "s#^MANAGEMENT_API_URL=.*#MANAGEMENT_API_URL=$URL_ESC#" \
		-e "s#^ENROLLMENT_TOKEN=.*#ENROLLMENT_TOKEN=$TOKEN_ESC#" \
		/usr/local/etc/olv-agent/agent.conf
	echo "  wrote /usr/local/etc/olv-agent/agent.conf"
fi

echo "  installing rc.d service file"
install -m 0755 "$ASSET_DIR/olv-agent.rc" /usr/local/etc/rc.d/olv-agent

echo "[5/6] enabling + starting service"
sysrc olv_agent_enable=YES >/dev/null
# Start in the background so the installer returns even if the agent's
# first enrollment handshake takes a while. service(8) otherwise waits
# for rc.d to return, and `daemon -f` can block briefly until the child
# detaches — which on a slow-network host looks like a hang.
(
	service olv-agent restart || service olv-agent start
) >/var/log/olv-agent-install.log 2>&1 &
SVC_PID=$!
# Give it up to 10s to fork the daemon; don't block longer.
WAITED=0
while kill -0 "$SVC_PID" 2>/dev/null && [ "$WAITED" -lt 10 ]; do
	sleep 1
	WAITED=$((WAITED + 1))
done
if kill -0 "$SVC_PID" 2>/dev/null; then
	echo "  service start still running after ${WAITED}s — continuing; check /var/log/olv-agent-install.log"
else
	wait "$SVC_PID" 2>/dev/null || true
	echo "  service start returned"
fi

echo "[6/6] done."
echo
echo "Config : /usr/local/etc/olv-agent/agent.conf"
echo "Logs   : tail -f /var/log/olv-agent.log"
echo "Restart: service olv-agent restart"
