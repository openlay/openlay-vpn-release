// Resolvers for typed targets/ingress on application_servers and
// route_policies (introduced after dropping client-side localhost).
//
// All resolvers are pure DB lookups against peers_meta.assigned_ip
// (cached at /api/connect time). They never call the agent — the agent
// is the source of truth, but peers_meta mirrors it close enough for
// dropdown population and rule expansion.
//
// "1 user = 1 active device" is product-side rule (see chat
// 2026-04-29). When that changes, expand resolveUserTarget to multi.
const { pool } = require('../db/pool');

/**
 * Pick the latest connected device for a user on a given server.
 * Returns { ip, iface, deviceId, alias } or null when offline.
 *
 * Rule: latest = peers_meta row joined to devices, sorted by
 * devices.last_connect_at DESC. assigned_ip must be present (i.e. peer
 * actually exists). Falls back to peers_meta.created_at when device
 * row is missing (legacy).
 */
async function resolveUserPeerOnServer(serverId, userId) {
  const { rows } = await pool.query(
    `SELECT pm.assigned_ip::text       AS ip,
            pm.interface_name          AS iface,
            pm.device_id               AS device_id,
            pm.alias                   AS alias
       FROM peers_meta pm
       LEFT JOIN devices d ON d.id = pm.device_id
      WHERE pm.server_id = $1
        AND pm.user_id   = $2
        AND pm.assigned_ip IS NOT NULL
        AND COALESCE(pm.is_expired, FALSE) = FALSE
      ORDER BY COALESCE(d.last_connect_at, pm.created_at) DESC
      LIMIT 1`,
    [serverId, userId]
  );
  return rows[0] || null;
}

/**
 * Resolve a specific device's current peer on this server. Returns
 * { ip, iface, alias } or null when offline.
 */
async function resolveDevicePeerOnServer(serverId, deviceId) {
  const { rows } = await pool.query(
    `SELECT assigned_ip::text AS ip,
            interface_name    AS iface,
            alias             AS alias
       FROM peers_meta
      WHERE server_id   = $1
        AND device_id   = $2
        AND assigned_ip IS NOT NULL
        AND COALESCE(is_expired, FALSE) = FALSE
      ORDER BY created_at DESC
      LIMIT 1`,
    [serverId, deviceId]
  );
  return rows[0] || null;
}

/**
 * Application Server target resolution. Used at /api/connect time when
 * surfacing the user's reachable apps. Output shape:
 *   { ip: "10.88.0.42" | null, reachable: true|false }
 * Caller renders the entry either way; client decides whether to show
 * an "unreachable" badge.
 */
async function resolveAppServerTarget(app, serverId) {
  if (app.target_type === 'ip') {
    // Static — always reachable from VPN routing standpoint.
    return { ip: app.ip, reachable: true };
  }
  if (app.target_type === 'user') {
    const peer = await resolveUserPeerOnServer(serverId, app.target_user_id);
    return peer ? { ip: peer.ip, reachable: true }
                : { ip: null, reachable: false };
  }
  if (app.target_type === 'device') {
    const peer = await resolveDevicePeerOnServer(serverId, app.target_device_id);
    return peer ? { ip: peer.ip, reachable: true }
                : { ip: null, reachable: false };
  }
  return { ip: null, reachable: false };
}

/**
 * Route Policy ingress resolution. Returns { srcCIDR, ingressIface }
 * suitable for agent's routerAddPolicy / routerUpdatePolicy. For
 * non-custom types we auto-derive the iface from the resolved peer's
 * interface_name; admin doesn't pick.
 *
 * Multi-IP cases (ingress_type='users' with N>1 or 'group') emit pf
 * set syntax: `{ 10.88.0.42, 10.88.0.43 }`. Agent's pf renderer just
 * concatenates "from <srcCIDR>" so this works as-is.
 *
 * Empty resolution (no online peer matching the reference) → returns
 * srcCIDR='' which agent treats as "never match" via a deliberate
 * `from no-route` clause emitted upstream. Caller should detect empty
 * and skip pushing rather than letting agent see "any".
 */
async function resolvePolicyIngress(policy, serverId, dbClient = pool) {
  if (policy.ingress_type === 'custom' || !policy.ingress_type) {
    return {
      srcCIDR: policy.src_cidr || '',
      ingressIface: policy.ingress_iface || '',
      resolvedIPs: policy.src_cidr ? [policy.src_cidr] : [],
    };
  }

  let userIds = [];
  if (policy.ingress_type === 'users') {
    const { rows } = await dbClient.query(
      'SELECT user_id FROM route_policy_users WHERE policy_id = $1',
      [policy.id]
    );
    userIds = rows.map(r => r.user_id);
  } else if (policy.ingress_type === 'group') {
    const { rows } = await dbClient.query(
      `SELECT user_id FROM user_group_members WHERE user_group_id = $1`,
      [policy.ingress_group_id]
    );
    userIds = rows.map(r => r.user_id);
  } else if (policy.ingress_type === 'device') {
    const peer = await resolveDevicePeerOnServer(serverId, policy.ingress_device_id);
    if (!peer) return { srcCIDR: '', ingressIface: '', resolvedIPs: [] };
    return {
      srcCIDR: `${peer.ip}/32`,
      ingressIface: peer.iface,
      resolvedIPs: [`${peer.ip}/32`],
    };
  }

  // users / group → expand to peer IPs (latest device per user)
  const peers = [];
  for (const uid of userIds) {
    const p = await resolveUserPeerOnServer(serverId, uid);
    if (p) peers.push(p);
  }
  if (peers.length === 0) {
    return { srcCIDR: '', ingressIface: '', resolvedIPs: [] };
  }
  // Pick iface from the first peer; if peers span multiple ifaces,
  // emit one rule per unique iface — but for v1 we collapse to the
  // most-common iface and skip outliers (rare in practice).
  const ifaceCounts = peers.reduce((m, p) => (m[p.iface] = (m[p.iface] || 0) + 1, m), {});
  const dominantIface = Object.entries(ifaceCounts).sort((a, b) => b[1] - a[1])[0][0];
  const matching = peers.filter(p => p.iface === dominantIface);
  const ips = matching.map(p => `${p.ip}/32`);
  const srcCIDR = ips.length === 1 ? ips[0] : `{ ${ips.join(', ')} }`;
  return { srcCIDR, ingressIface: dominantIface, resolvedIPs: ips };
}

module.exports = {
  resolveUserPeerOnServer,
  resolveDevicePeerOnServer,
  resolveAppServerTarget,
  resolvePolicyIngress,
};
