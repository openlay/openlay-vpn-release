const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');

/**
 * Resolve a firewall rule side (src or dst) to a list of IP/CIDR strings.
 *
 * A rule side can be specified as any ONE of:
 *   - { ip: "10.0.0.5" } or { ip: "10.0.0.0/24" }  — literal
 *   - { zoneId: 42 }                                — resolve to members
 *   - { aliasId: 7 }                                — resolve to addresses array
 *   - { userId: "uuid" }                            — resolve to all peer IPs of that user on this server
 *   - {} / { ip: null }                             — "any" → returns [null]
 *
 * Always returns an array (never throws on empty members — just returns []).
 * Caller should treat [null] as the "no filter" sentinel and [] as "zone resolved to nothing".
 */

async function resolveSide(serverId, side) {
  if (!side) return [null];
  if (side.zoneId !== undefined && side.zoneId !== null) {
    return resolveZone(serverId, side.zoneId);
  }
  if (side.aliasId !== undefined && side.aliasId !== null) {
    return resolveAlias(serverId, side.aliasId);
  }
  if (side.userId) {
    return resolveUser(serverId, side.userId);
  }
  if (side.ip) return [side.ip];
  return [null];
}

async function resolveZone(serverId, zoneId) {
  const { rows: zones } = await pool.query(
    'SELECT * FROM firewall_zones WHERE id = $1 AND server_id = $2',
    [zoneId, serverId]
  );
  if (zones.length === 0) throw new Error(`Zone ${zoneId} not found`);
  const zone = zones[0];

  if (zone.name === 'any' || zone.name === 'wan') return ['0.0.0.0/0'];

  if (zone.name === 'vpn-peers') {
    return resolveVpnPeers(serverId);
  }

  const { rows: members } = await pool.query(
    'SELECT * FROM firewall_zone_members WHERE zone_id = $1',
    [zoneId]
  );
  const ips = [];
  for (const m of members) {
    switch (m.member_type) {
      case 'ip':
        ips.push(m.member_value);
        break;
      case 'subnet': {
        const { rows: subs } = await pool.query(
          'SELECT cidr FROM subnets WHERE id = $1',
          [m.member_value]
        );
        if (subs.length > 0) ips.push(subs[0].cidr);
        break;
      }
      case 'user': {
        const userIps = await resolveUser(serverId, m.member_value);
        ips.push(...userIps);
        break;
      }
      case 'interface': {
        const { rows: subs } = await pool.query(
          'SELECT cidr FROM subnets WHERE server_id = $1 AND interface_name = $2',
          [serverId, m.member_value]
        );
        for (const s of subs) ips.push(s.cidr);
        break;
      }
    }
  }
  return ips;
}

async function resolveAlias(serverId, aliasId) {
  const { rows } = await pool.query(
    'SELECT addresses FROM firewall_aliases WHERE id = $1 AND server_id = $2',
    [aliasId, serverId]
  );
  if (rows.length === 0) throw new Error(`Alias ${aliasId} not found`);
  return rows[0].addresses || [];
}

async function resolveUser(serverId, userId) {
  const { rows: peerRows } = await pool.query(
    `SELECT pm.public_key, s.interface_name
     FROM peers_meta pm
     JOIN subnets s ON pm.subnet_id = s.id
     WHERE pm.user_id = $1 AND pm.server_id = $2`,
    [userId, serverId]
  );
  if (peerRows.length === 0) return [];
  const client = new AgentClient(serverId);
  const ips = [];
  try {
    for (const pr of peerRows) {
      try {
        const peer = await client.request('getPeer', { iface: pr.interface_name, pubkey: pr.public_key });
        if (peer && peer.allowedIPs) {
          ips.push(...peer.allowedIPs.split(',').map(ip => ip.trim()).filter(Boolean));
        }
      } catch {}
    }
  } catch {}
  // Fallback: if agent unreachable, try device_static_ips
  if (ips.length === 0) {
    const { rows: staticIps } = await pool.query(
      `SELECT DISTINCT dsi.ip_address
       FROM device_static_ips dsi
       JOIN devices d ON d.id = dsi.device_id
       WHERE d.user_id = $1 AND dsi.server_id = $2`,
      [userId, serverId]
    );
    ips.push(...staticIps.map(r => `${r.ip_address}/32`));
  }
  return ips;
}

async function resolveVpnPeers(serverId) {
  const client = new AgentClient(serverId);
  try {
    const { interfaces } = await client.listInterfaces();
    const ips = [];
    for (const iface of (interfaces || [])) {
      const { peers } = await client.request('listPeers', { iface });
      for (const p of (peers || [])) {
        if (p.allowedIPs) ips.push(...p.allowedIPs.split(',').map(ip => ip.trim()).filter(Boolean));
      }
    }
    return ips.length > 0 ? ips : [];
  } catch {
    return [];
  }
}

module.exports = { resolveSide, resolveZone, resolveAlias, resolveUser, resolveVpnPeers };
