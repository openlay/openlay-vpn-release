const { pool } = require('../db/pool');
const { isValidCidr } = require('./subnetUtils');

/**
 * Normalize CIDR: 10.0.0.1/24 → 10.0.0.0/24
 */
function normalizeCidr(cidr) {
  const [ip, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const octets = ip.split('.').map(Number);
  const ipLong = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const network = ipLong & mask;
  return [
    (network >>> 24) & 255,
    (network >>> 16) & 255,
    (network >>> 8) & 255,
    network & 255,
  ].join('.') + '/' + prefix;
}

/**
 * Upsert subnets from interface addresses.
 * Each interface address (e.g. "10.0.0.1/24") becomes a subnet.
 */
async function syncSubnets(serverId, interfaces) {
  if (!interfaces || !Array.isArray(interfaces) || interfaces.length === 0) return [];

  const created = [];

  for (const iface of interfaces) {
    if (!iface.name || !iface.address) continue;

    const addresses = iface.address.split(',').map(a => a.trim()).filter(Boolean);

    for (const addr of addresses) {
      if (addr.includes(':')) continue;
      if (!isValidCidr(addr)) continue;

      const prefix = parseInt(addr.split('/')[1], 10);
      if (prefix >= 32) continue;

      const cidr = normalizeCidr(addr);

      try {
        const { rows } = await pool.query(
          `INSERT INTO subnets (server_id, interface_name, cidr, name, description)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (server_id, cidr) DO NOTHING
           RETURNING id, cidr`,
          [serverId, iface.name, cidr, `${iface.name} default`, `Auto-registered from interface ${iface.name}`]
        );
        if (rows.length > 0) {
          created.push({ id: rows[0].id, cidr: rows[0].cidr, interface: iface.name });
        }
      } catch (err) {
        console.warn(`[subnetSync] Failed to create subnet ${cidr} for ${iface.name}: ${err.message}`);
      }
    }
  }

  return created;
}

module.exports = { syncSubnets, normalizeCidr };
