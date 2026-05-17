#!/bin/sh
# /usr/local/sbin/olv-agent-upgrade.sh
#
# Idempotent agent binary upgrade. Run as root on the FreeBSD VPN box:
#
#   ./upgrade.sh ./olv-agent-freebsd-amd64
#   ./upgrade.sh https://example.com/olv-agent-freebsd-amd64
#
# What this does, in order:
#
#   1. Stage the new binary at /tmp/olv-agent.new + verify it runs.
#   2. Read MANAGEMENT_API_URL from agent.conf, probe the cert there.
#      If the leaf cert has NO subjectAltName (Go 1.15+ rejects CN-only
#      certs in strict-verify mode — see 2026-05-17 incident on mngk:
#      "x509: certificate relies on legacy Common Name field, use SANs
#      instead"), ensure OLV_MGMT_INSECURE_TLS=true is in agent.conf so
#      the upgraded binary keeps connecting.
#   3. Stop service, back up the existing binary to
#      /usr/local/sbin/olv-agent.bak-<unixtime>, mv the new one in.
#   4. Start service + tail the log so the operator sees the
#      "[ws] connected" or the actual failure within seconds.
#
# Why this script exists: a plain `mv` upgrade across the Phase 2.2 cut
# (which removed the hardcoded InsecureSkipVerify) silently broke any
# agent talking to a CN-only mgmt cert until the operator pieced
# together the env-var rename. This script makes the upgrade safe by
# default; explicit `OLV_MGMT_TLS_CERT=<path>` already in agent.conf is
# preserved and takes precedence.
set -e

err() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[upgrade] $*"; }

SRC="${1:-}"
[ -n "$SRC" ] || err "usage: $0 <path-or-url-to-new-binary>"

CONF=/usr/local/etc/olv-agent/agent.conf
SBIN=/usr/local/sbin/olv-agent
STAGE=/tmp/olv-agent.new

[ -f "$CONF" ] || err "agent.conf not found at $CONF"
[ -x "$SBIN" ] || err "existing binary not at $SBIN (run install.sh first)"

# 1. Stage the new binary.
case "$SRC" in
  http://*|https://*)
    info "fetching $SRC"
    fetch -qo "$STAGE" "$SRC" || err "fetch failed"
    ;;
  *)
    [ -f "$SRC" ] || err "no such file: $SRC"
    cp "$SRC" "$STAGE"
    ;;
esac
chmod +x "$STAGE"
NEW_VER=$("$STAGE" -version 2>/dev/null) || err "new binary does not run"
OLD_VER=$("$SBIN" -version 2>/dev/null || echo "?")
info "old: $OLD_VER"
info "new: $NEW_VER"
[ "$OLD_VER" = "$NEW_VER" ] && info "(same version — proceeding anyway in case env-var migration is needed)"

# 2. Probe mgmt cert for SAN; if missing, set OLV_MGMT_INSECURE_TLS=true.
#    Already-set values are preserved (explicit operator override wins).
if grep -q '^OLV_MGMT_INSECURE_TLS=' "$CONF" || grep -q '^OLV_MGMT_TLS_CERT=' "$CONF"; then
  info "TLS verification already configured in agent.conf — leaving as-is"
else
  MGMT_URL=$(awk -F= '$1=="MANAGEMENT_API_URL" {print $2; exit}' "$CONF" | tr -d '"' | tr -d "'")
  if [ -z "$MGMT_URL" ]; then
    err "MANAGEMENT_API_URL is empty in $CONF — cannot probe cert; set TLS options manually before upgrading"
  fi
  HOST=$(echo "$MGMT_URL" | sed -E 's|^https?://||; s|/.*$||')
  HOSTNAME=$(echo "$HOST" | cut -d: -f1)
  PORT=$(echo "$HOST" | awk -F: 'NF>1 {print $2; exit} {print 3084}')
  info "probing TLS cert at $HOSTNAME:$PORT for SAN extension"

  CERT_TEXT=$(echo | openssl s_client -connect "$HOSTNAME:$PORT" -servername "$HOSTNAME" 2>/dev/null \
              | openssl x509 -noout -text 2>/dev/null || true)
  if [ -z "$CERT_TEXT" ]; then
    info "  could not retrieve cert (mgmt unreachable?) — defaulting to insecure to avoid lockout"
    NEEDS_INSECURE=1
  elif echo "$CERT_TEXT" | grep -q "X509v3 Subject Alternative Name"; then
    info "  cert has SAN — strict TLS verification will work, no flag needed"
    NEEDS_INSECURE=0
  else
    info "  cert is CN-only (no SAN) — Go strict verify would reject it"
    NEEDS_INSECURE=1
  fi

  if [ "$NEEDS_INSECURE" = "1" ]; then
    info "  appending OLV_MGMT_INSECURE_TLS=true to $CONF"
    {
      echo ""
      echo "# Auto-added by olv-agent-upgrade.sh on $(date -u +%FT%TZ): the management"
      echo "# server's TLS cert at $MGMT_URL has no SAN, so Go's strict x509"
      echo "# verifier would reject it. To remove this flag, regenerate the mgmt"
      echo "# cert with subjectAltName=DNS:$HOSTNAME and run upgrade.sh again."
      echo "OLV_MGMT_INSECURE_TLS=true"
    } >> "$CONF"
  fi
fi

# 3. Stop + swap binary.
info "stopping service"
service olv-agent stop || true
BAK="${SBIN}.bak-$(date +%s)"
info "backing up old binary to $BAK"
cp "$SBIN" "$BAK"
mv "$STAGE" "$SBIN"
chown root:wheel "$SBIN"
chmod 755 "$SBIN"

# 4. Start + verify.
info "starting service"
service olv-agent start
sleep 3
service olv-agent status

info "tailing log for 10 seconds — look for '[ws] connected as ...'"
sleep 10
tail -15 /var/log/olv-agent.log

info "done. Rollback: service olv-agent stop && mv $BAK $SBIN && service olv-agent start"
