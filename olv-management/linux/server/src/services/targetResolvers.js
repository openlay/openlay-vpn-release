// Resolvers for typed targets/ingress on application_servers and
// route_policies (introduced after dropping client-side localhost).
//
// Primary path: pure DB lookup against peers_meta.assigned_ip (cached
// at /api/connect time). Fast.
//
// Fallback: when peers_meta has the row but assigned_ip is NULL —
// happens for peers that existed BEFORE migration 047 added the
// column — fall through to agent and read the live AllowedIPs. The
// resolved IP is written back so subsequent calls hit the cache. This
// pays the agent roundtrip exactly once per stale peer.
//
// "1 user = 1 active device" is product-side rule (see chat
// 2026-04-29). When that changes, expand resolveUserTarget to multi.
const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');

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
  // host() returns the bare address. assigned_ip::text would emit
  // "10.88.0.5/32" for IPv4 hosts, leading to "10.88.0.5/32/32"
  // when callers append a /32 suffix.
  const { rows } = await pool.query(
    `SELECT host(pm.assigned_ip)        AS ip,
            pm.interface_name           AS iface,
            pm.device_id                AS device_id,
            pm.alias                    AS alias,
            pm.public_key               AS public_key,
            pm.assigned_ip IS NULL      AS need_backfill
       FROM peers_meta pm
       LEFT JOIN devices d ON d.id = pm.device_id
      WHERE pm.server_id = $1
        AND pm.user_id   = $2
        AND COALESCE(pm.is_expired, FALSE) = FALSE
      ORDER BY (pm.assigned_ip IS NOT NULL) DESC,
               COALESCE(d.last_connect_at, pm.created_at) DESC
      LIMIT 1`,
    [serverId, userId]
  );
  if (rows.length === 0) return null;
  const r = rows[0];
  if (r.ip) return r;
  // Cache miss — backfill from agent state.
  const ip = await backfillAssignedIp(serverId, r.iface, r.public_key);
  return ip ? { ...r, ip } : null;
}

/**
 * Resolve a specific device's current peer on this server. Returns
 * { ip, iface, alias } or null when offline.
 */
async function resolveDevicePeerOnServer(serverId, deviceId) {
  const { rows } = await pool.query(
    `SELECT host(assigned_ip) AS ip,
            interface_name    AS iface,
            alias             AS alias,
            public_key        AS public_key
       FROM peers_meta
      WHERE server_id   = $1
        AND device_id   = $2
        AND COALESCE(is_expired, FALSE) = FALSE
      ORDER BY (assigned_ip IS NOT NULL) DESC, created_at DESC
      LIMIT 1`,
    [serverId, deviceId]
  );
  if (rows.length === 0) return null;
  const r = rows[0];
  if (r.ip) return r;
  const ip = await backfillAssignedIp(serverId, r.iface, r.public_key);
  return ip ? { ...r, ip } : null;
}

/**
 * Pull live AllowedIPs from the agent for a single peer and write back
 * to peers_meta.assigned_ip so subsequent resolves hit the cache. Used
 * to reconcile peers_meta rows that pre-date migration 047 (which
 * added the column). Returns the bare IP string or null.
 */
async function backfillAssignedIp(serverId, iface, publicKey) {
  if (!iface || !publicKey) return null;
  try {
    const client = new AgentClient(serverId);
    const data = await client.getInterface(iface);
    const peer = (data.peers || []).find(p => p.publicKey === publicKey);
    if (!peer) return null;
    const allowed = (peer.allowedIPs || '').split(',').map(s => s.trim()).filter(Boolean);
    // Prefer /32 — that's the host route the connect endpoint provisioned.
    // Fall back to the first AllowedIP (strip mask) if no /32 present.
    const host32 = allowed.find(x => x.endsWith('/32'));
    const ip = host32 ? host32.split('/')[0] : (allowed[0] || '').split('/')[0];
    if (!ip) return null;
    await pool.query(
      `UPDATE peers_meta SET assigned_ip = $1
        WHERE server_id = $2 AND interface_name = $3 AND public_key = $4`,
      [ip, serverId, iface, publicKey]
    );
    return ip;
  } catch (err) {
    console.error(`[targetResolvers] backfill iface=${iface} pubkey=${publicKey?.slice(0,8)}…: ${err.message}`);
    return null;
  }
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

/**
 * Bulk backfill every peer on a server whose assigned_ip is NULL by
 * walking the agent's interface state. Called on agent register so a
 * fresh connection reconciles cache automatically — no manual step,
 * no per-resolve roundtrip latency.
 */
async function backfillServerAssignedIps(serverId) {
  const { rows: stale } = await pool.query(
    `SELECT public_key, interface_name, user_id FROM peers_meta
      WHERE server_id = $1 AND assigned_ip IS NULL
        AND COALESCE(is_expired, FALSE) = FALSE`,
    [serverId]
  );
  if (stale.length === 0) return { backfilled: 0 };

  // Group by iface so we list each iface once.
  const byIface = new Map();
  for (const r of stale) {
    if (!byIface.has(r.interface_name)) byIface.set(r.interface_name, new Set());
    byIface.get(r.interface_name).add(r.public_key);
  }

  const client = new AgentClient(serverId);
  let backfilled = 0;
  const recoveredUserIds = new Set();
  for (const [iface, pubkeySet] of byIface) {
    try {
      const data = await client.getInterface(iface);
      for (const peer of (data.peers || [])) {
        if (!pubkeySet.has(peer.publicKey)) continue;
        const allowed = (peer.allowedIPs || '').split(',').map(s => s.trim()).filter(Boolean);
        const host32 = allowed.find(x => x.endsWith('/32'));
        const ip = host32 ? host32.split('/')[0] : (allowed[0] || '').split('/')[0];
        if (!ip) continue;
        await pool.query(
          `UPDATE peers_meta SET assigned_ip = $1
            WHERE server_id = $2 AND interface_name = $3 AND public_key = $4`,
          [ip, serverId, iface, peer.publicKey]
        );
        backfilled++;
        // Capture user_id for downstream resync — these users now
        // have a resolvable IP that previous syncs may have skipped.
        const owner = stale.find(s => s.public_key === peer.publicKey)?.user_id;
        if (owner) recoveredUserIds.add(owner);
      }
    } catch (err) {
      console.error(`[targetResolvers] bulk backfill server=${serverId} iface=${iface}: ${err.message}`);
    }
  }
  if (backfilled > 0) {
    console.log(`[targetResolvers] backfilled ${backfilled} peer(s) on server=${serverId}`);
    // Auto-fire downstream resync. Users that just gained a usable IP
    // were silently skipped on prior CRUD/sync calls (rules pushed
    // with their IP missing from srcIP set). Re-run those syncs now
    // that resolve will succeed. Lazy-require to avoid a circular
    // import (ruleOrchestrator → policyResync/appServerFirewall →
    // targetResolvers).
    if (recoveredUserIds.size > 0) {
      try {
        const { resyncRulesByUsers } = require('./ruleOrchestrator');
        await resyncRulesByUsers(serverId, [...recoveredUserIds]);
      } catch (err) {
        console.error(`[targetResolvers] auto-resync after backfill server=${serverId}: ${err.message}`);
      }
    }
  }
  return { backfilled, recoveredUserCount: recoveredUserIds.size };
}

module.exports = {
  resolveUserPeerOnServer,
  resolveDevicePeerOnServer,
  resolveAppServerTarget,
  resolvePolicyIngress,
  backfillServerAssignedIps,
};
