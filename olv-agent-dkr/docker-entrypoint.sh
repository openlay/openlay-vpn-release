#!/bin/bash
set -e

# Create TUN device if missing (may already exist via host)
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200 2>/dev/null || true
  chmod 600 /dev/net/tun 2>/dev/null || true
fi

# Ensure ip_forward is enabled (may fail in container, host should have it)
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# Fix PostUp sysctl in existing configs to not fail in Docker
for conf in /etc/wireguard/*.conf; do
  [ -f "$conf" ] || continue
  sed -i 's%sysctl -w net.ipv4.ip_forward=1;%sysctl -w net.ipv4.ip_forward=1 || true;%' "$conf" 2>/dev/null || true
done

# Restore WireGuard interfaces from persisted configs
for conf in /etc/wireguard/*.conf; do
  [ -f "$conf" ] || continue
  iface=$(basename "$conf" .conf)
  # Down first in case kernel still has a stale interface
  wg-quick down "$iface" 2>/dev/null || true
  wg-quick up "$iface" 2>/dev/null || echo "Warning: failed to bring up $iface"
done

# Install iproute2-tc if not present (for rate limiting)
apk add --no-cache iproute2-tc 2>/dev/null || true

exec "$@"
