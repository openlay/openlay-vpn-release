/**
 * Build a WireGuard client configuration file string.
 */
function buildClientConfig({ privateKey, address, dns, serverPublicKey, serverEndpoint, allowedIPs, presharedKey, persistentKeepalive }) {
  const lines = ['[Interface]'];
  lines.push(`PrivateKey = ${privateKey}`);
  lines.push(`Address = ${address}`);
  if (dns) lines.push(`DNS = ${dns}`);
  lines.push('');
  lines.push('[Peer]');
  lines.push(`PublicKey = ${serverPublicKey}`);
  if (presharedKey) lines.push(`PresharedKey = ${presharedKey}`);
  lines.push(`Endpoint = ${serverEndpoint}`);
  lines.push(`AllowedIPs = ${allowedIPs || '0.0.0.0/0, ::/0'}`);
  if (persistentKeepalive) lines.push(`PersistentKeepalive = ${persistentKeepalive}`);
  lines.push('');
  return lines.join('\n');
}

module.exports = { buildClientConfig };
