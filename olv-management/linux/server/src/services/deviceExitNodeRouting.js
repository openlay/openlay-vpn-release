// Auto-manage hub-and-spoke "exit node" routing: a peer (consumer) has
// its WAN-bound traffic redirected on the agent to ANOTHER peer (exit
// node, typically a Linux client) which then MASQUERADEs out its own
// physical WAN. Tailscale-style.
//
// Assignment lives at the PROFILE level — `device_profiles.exit_node_device_id`
// (migration 055). Every device on a profile inherits the same exit-node
// pointer. This matches the existing policy-bundle shape (allow_wan_access,
// can_be_exit_node, allowed_ips, exclusion_ips, require_posture).
//
// Two roles per device, both maintained here:
//   1. CONSUMER role:  device's profile has exit_node_device_id IS NOT NULL
//      → install pf route_policy on agent named "exit-<deviceId>":
//         pass in quick on <wgIface> route-to (<wgIface> <exitPeer.ip>)
//              from <consumerPeer.ip>/32 to any
//   2. EXIT-NODE role: at least one profile has exit_node_device_id == this id
//      → set this peer's AllowedIPs on agent to "<peer.ip>/32, 0.0.0.0/0"
//        so WG cryptokey routing accepts the diverted packets. When the
//        last consumer leaves, restore to bare "<peer.ip>/32".
//
// Triggers (wired by callers):
//   - PUT /api/admin/device-profiles/:id when can_be_exit_node OR
//     exit_node_device_id changes — fan out to every device on profile
//   - PUT /api/admin/devices/:id when profile_id / status changes —
//     because device's effective exit-node pointer is via profile
//   - resyncRulesByUsers chain (peer connect/disconnect, key rotation) —
//     covers both directions: device-as-consumer AND consumers-of-this-exit
//   - DELETE /api/admin/devices/:id (orphan cleanup)
//
// Edge cases:
//   - consumer offline      -> tear down (no rule to install for absent peer)
//   - exit node offline     -> tear down consumer's PBR rule (graceful
//                              fall-back to agent gateway, no blackhole)
//   - consumer & exit on different WG interfaces -> skip (cryptokey
//     routing is interface-local; cross-iface routing would need extra
//     plumbing not in scope for v1)
//   - capability revoked    -> sync sees no can_be_exit_node, tears down
//   - profile points at one of its OWN member devices as exit node ->
//     that member would self-loop. Validation in admin route blocks at
//     write time, sync also short-circuits if encountered.
//
// LIMITATION (v1): only ONE exit node per WG interface — WG cryptokey
// routing is longest-prefix-match and can only resolve 0.0.0.0/0 to one
// peer. A second exit node on the same iface would clash. Multi-exit
// per server requires multiple WG interfaces (out of scope).

const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');
const { resolveDevicePeerOnServer } = require('./targetResolvers');
const { withServerLock } = require('./serverLock');

const POLICY_NAME_PREFIX = 'exit-';
// Sit just below the 1000+ "auto rule" band so route-to wins over the
// default block_wan ACCEPT — but high enough that admin policies stay
// authoritative.
const POLICY_PRIORITY = 900;

// Only Linux clients implement the PostUp MASQUERADE / ip_forward setup
// needed to actually forward consumer traffic. iOS/macOS NetworkExtension
// can't, Windows isn't wired, Android is a placeholder. Defense in depth:
// admin route validation already blocks non-Linux exit nodes, but if an
// OS changes after assignment we don't want to push 0/0 to a peer that
// would blackhole the diverted traffic.
const EXIT_NODE_CAPABLE_OS = new Set(['linux']);

async function deviceOsCapableOfExitNode(deviceId) {
  const { rows } = await pool.query('SELECT os FROM devices WHERE id = $1', [deviceId]);
  return EXIT_NODE_CAPABLE_OS.has(rows[0]?.os);
}

function policyNameFor(consumerDeviceId) { return `${POLICY_NAME_PREFIX}${consumerDeviceId}`; }
function isExitNodeManagedPolicyName(name) {
  return typeof name === 'string' && name.startsWith(POLICY_NAME_PREFIX);
}

/**
 * Resolve the exit-node device id for a CONSUMER device. Returns null
 * when the device has no profile or the profile has no exit-node set.
 */
async function exitNodeIdForConsumer(deviceId) {
  const { rows } = await pool.query(
    `SELECT dp.exit_node_device_id
       FROM devices d
       LEFT JOIN device_profiles dp ON dp.id = d.profile_id
      WHERE d.id = $1`,
    [deviceId]
  );
  return rows[0]?.exit_node_device_id || null;
}

/**
 * Remove a single named exit-node policy from agent. Idempotent — silent
 * no-op when the rule isn't on the agent.
 */
async function removeNamedPolicy(client, name) {
  try {
    const list = await client.routerListPolicies();
    const onAgent = (list?.policies || []).find(p => p.name === name);
    if (onAgent) {
      await client.routerRemovePolicy(onAgent.id);
      return 1;
    }
  } catch (err) {
    console.error(`[deviceExitNodeRouting] remove policy ${name} failed:`, err.message);
  }
  return 0;
}

/**
 * Idempotent teardown of the exit-node rule for `deviceId` AS A CONSUMER
 * on this server. Used by route DELETE handlers and from sync paths that
 * want to clear state before re-evaluating.
 *
 * Does NOT touch the device's exit-peer AllowedIPs (that's the OTHER
 * role; caller can re-sync that separately if needed).
 */
async function removeDeviceExitNodeRules(serverId, deviceId) {
  const client = new AgentClient(serverId);
  return removeNamedPolicy(client, policyNameFor(deviceId));
}

/**
 * Count CONSUMERS currently using `exitNodeDeviceId` as their exit, on
 * this server. A device counts only when (a) it's enabled, (b) it has a
 * peer on this server (peers_meta row, non-expired), (c) its profile
 * points at the given exit-node id. Drives whether the exit-peer's
 * AllowedIPs needs 0/0 or just /32.
 */
async function countConsumersOf(serverId, exitNodeDeviceId) {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n
       FROM devices d
       JOIN device_profiles dp ON dp.id = d.profile_id
       JOIN peers_meta pm ON pm.device_id = d.id
                          AND pm.server_id = $2
                          AND COALESCE(pm.is_expired, FALSE) = FALSE
      WHERE dp.exit_node_device_id = $1
        AND d.status = 'enabled'`,
    [exitNodeDeviceId, serverId]
  );
  return rows[0]?.n || 0;
}

/**
 * Sync the EXIT-NODE-side AllowedIPs for `deviceId` on this server. If
 * any consumer references it, set "<peer.ip>/32, 0.0.0.0/0"; otherwise
 * restore bare "<peer.ip>/32". No-op when the device isn't actually an
 * exit-node-capable peer on this server.
 */
async function syncExitPeerAllowedIPs(serverId, deviceId) {
  const exitPeer = await resolveDevicePeerOnServer(serverId, deviceId);
  if (!exitPeer) return { skipped: true, reason: 'exit-peer-offline' };

  // OS gate: only Linux can actually MASQUERADE forwarded packets. Treat
  // a non-Linux device as if it has 0 consumers — restores bare /32 even
  // if some profile still has it pinned as exit_node_device_id.
  const isCapable = await deviceOsCapableOfExitNode(deviceId);
  const consumers = isCapable ? await countConsumersOf(serverId, deviceId) : 0;
  const target = consumers > 0
    ? `${exitPeer.ip}/32, 0.0.0.0/0`
    : `${exitPeer.ip}/32`;

  const client = new AgentClient(serverId);
  try {
    await client.setPeerAllowedIPs(exitPeer.iface, exitPeer.public_key, target);
    return { allowedIPs: target, consumers };
  } catch (err) {
    console.error(`[deviceExitNodeRouting] setPeerAllowedIPs exit=${deviceId} server=${serverId}: ${err.message}`);
    return { skipped: true, reason: 'set-allowed-failed', error: err.message };
  }
}

/**
 * Sync the CONSUMER-side PBR rule for `deviceId` on this server. Always
 * tear-down-then-rebuild to converge from any prior state. The exit-node
 * pointer comes from the device's profile.
 */
async function syncConsumerPolicy(serverId, deviceId) {
  const client = new AgentClient(serverId);
  await removeNamedPolicy(client, policyNameFor(deviceId));

  const { rows } = await pool.query(
    `SELECT d.status, dp.exit_node_device_id
       FROM devices d
       LEFT JOIN device_profiles dp ON dp.id = d.profile_id
      WHERE d.id = $1`,
    [deviceId]
  );
  const dev = rows[0];
  if (!dev) return { added: 0, reason: 'device-not-found' };
  if (dev.status !== 'enabled') return { added: 0, reason: 'device-not-enabled' };
  if (!dev.exit_node_device_id) return { added: 0, reason: 'no-exit-node-on-profile' };
  // Self-loop guard: a profile cannot point its OWN member device at
  // itself as the exit node — that device would route through itself.
  // Validators reject this at write time; double-check at runtime.
  if (dev.exit_node_device_id === deviceId) {
    return { added: 0, reason: 'self-loop-skipped' };
  }

  const consumerPeer = await resolveDevicePeerOnServer(serverId, deviceId);
  if (!consumerPeer) return { added: 0, reason: 'consumer-peer-offline' };
  const exitPeer = await resolveDevicePeerOnServer(serverId, dev.exit_node_device_id);
  // Exit offline → graceful fall-back: leave PBR uninstalled, traffic
  // hits the agent's default WAN gateway as it did pre-feature.
  if (!exitPeer) return { added: 0, reason: 'exit-peer-offline' };

  // Cryptokey routing is per-WG-interface; both peers must share one.
  if (consumerPeer.iface !== exitPeer.iface) {
    return { added: 0, reason: 'iface-mismatch' };
  }

  // OS gate: don't install a PBR rule pointing at a non-Linux peer —
  // it can't forward, so we'd blackhole the consumer's WAN traffic.
  if (!await deviceOsCapableOfExitNode(dev.exit_node_device_id)) {
    return { added: 0, reason: 'exit-device-not-linux' };
  }

  try {
    await client.routerAddPolicy({
      name: policyNameFor(deviceId),
      priority: POLICY_PRIORITY,
      ingressIface: consumerPeer.iface,
      srcCIDR: `${consumerPeer.ip}/32`,
      dstCIDR: '0.0.0.0/0',
      protocol: '',
      fib: 0,
      action: 'route-to',
      gatewayIface: consumerPeer.iface,
      gateway: exitPeer.ip,
      description: `auto: exit-node routing (consumer ${deviceId} -> exit ${dev.exit_node_device_id})`,
      enabled: true,
    });
    return { added: 1, exitNodeDeviceId: dev.exit_node_device_id };
  } catch (err) {
    console.error(`[deviceExitNodeRouting] addPolicy device=${deviceId} server=${serverId}: ${err.message}`);
    return { added: 0, reason: 'add-policy-failed', error: err.message };
  }
}

/**
 * Tear down then (re)build BOTH roles for `deviceId` on one server.
 * Idempotent — safe to call regardless of prior state.
 */
async function syncDeviceExitNodeOnServer(serverId, deviceId) {
  return withServerLock(serverId, async () => {
    // Order matters: install allowedIPs BEFORE consumer policy so that the
    // first packet flowing through PBR isn't dropped by WG cryptokey
    // routing because the exit peer doesn't yet accept 0/0. (For consumer
    // role we tear down first and rebuild last; that path is fine.)
    const exit = await syncExitPeerAllowedIPs(serverId, deviceId);
    const consumer = await syncConsumerPolicy(serverId, deviceId);
    return { consumer, exit };
  });
}

/**
 * Sync this device on every server it has (or had) a peer on. Routed
 * through peers_meta so we catch every server the device has touched
 * even if the peer is currently expired.
 */
async function syncDeviceExitNodeAcrossServers(deviceId) {
  const { rows } = await pool.query(
    'SELECT DISTINCT server_id FROM peers_meta WHERE device_id = $1',
    [deviceId]
  );
  for (const r of rows) {
    try { await syncDeviceExitNodeOnServer(r.server_id, deviceId); }
    catch (err) {
      console.error(`[deviceExitNodeRouting] sync device=${deviceId} server=${r.server_id}: ${err.message}`);
    }
  }
}

/**
 * Profile-level fan-out — the main trigger when an admin flips
 * `exit_node_device_id` (assignment) or `can_be_exit_node` (capability)
 * on a profile. Every device on the profile is potentially gaining,
 * losing, or switching its exit-node pointer.
 *
 * `priorExitNodeDeviceId` (optional) — if the caller knows the previous
 * exit-node id (e.g. snapshotted in the route handler before the UPDATE),
 * passing it lets us also re-sync that device's exit-side AllowedIPs so
 * its consumer count drops to 0 and it reverts to bare /32.
 */
async function syncProfileExitNodeAcrossServers(profileId, priorExitNodeDeviceId = null) {
  // 1) Re-sync every device on this profile (consumer-side change).
  const { rows } = await pool.query(
    `SELECT id FROM devices WHERE profile_id = $1`,
    [profileId]
  );
  for (const r of rows) {
    try { await syncDeviceExitNodeAcrossServers(r.id); }
    catch (err) {
      console.error(`[deviceExitNodeRouting] profile sync device=${r.id}: ${err.message}`);
    }
  }

  // 2) Re-sync the NEW exit-node device's exit-side AllowedIPs (consumer
  // count went up). Look it up fresh from the profile.
  const { rows: profRows } = await pool.query(
    'SELECT exit_node_device_id FROM device_profiles WHERE id = $1',
    [profileId]
  );
  const newExit = profRows[0]?.exit_node_device_id || null;

  // 3) Build the set of "exit-node devices to re-sync the AllowedIPs of"
  // — the new exit (count went up) and the old one (count went down).
  const exitsToTouch = new Set([newExit, priorExitNodeDeviceId].filter(Boolean));
  for (const id of exitsToTouch) {
    try { await syncDeviceExitNodeAcrossServers(id); }
    catch (err) {
      console.error(`[deviceExitNodeRouting] profile sync exit-side ${id}: ${err.message}`);
    }
  }
}

/**
 * Chain entry from resyncRulesByUsers — called whenever any peer's IP
 * may have shifted (peer connect, disconnect, key rotation, etc.).
 *
 * Catches BOTH directions:
 *   (a) devices owned by these users that ARE consumers (their own peer
 *       moved → PBR srcCIDR needs updating)
 *   (b) devices owned by other users that POINT AT a device owned by
 *       these users (their exit peer moved → PBR gateway needs updating).
 *       The pointer is now via profile, so we look at every profile that
 *       references a device of these users as exit_node, then iterate
 *       devices on those profiles.
 */
async function syncExitNodeForUsers(serverId, userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return;
  const valid = userIds.filter(Boolean);
  if (valid.length === 0) return;

  const { rows } = await pool.query(
    `SELECT DISTINCT d.id FROM devices d
       LEFT JOIN device_profiles dp ON dp.id = d.profile_id
      WHERE d.user_id = ANY($1::text[])
         OR dp.exit_node_device_id IN (
              SELECT id FROM devices WHERE user_id = ANY($1::text[])
            )`,
    [valid]
  );
  for (const r of rows) {
    try { await syncDeviceExitNodeOnServer(serverId, r.id); }
    catch (err) {
      console.error(`[deviceExitNodeRouting] user-chain sync device=${r.id}: ${err.message}`);
    }
  }
}

module.exports = {
  policyNameFor,
  isExitNodeManagedPolicyName,
  exitNodeIdForConsumer,
  removeDeviceExitNodeRules,
  syncDeviceExitNodeOnServer,
  syncDeviceExitNodeAcrossServers,
  syncProfileExitNodeAcrossServers,
  syncExitNodeForUsers,
  syncExitPeerAllowedIPs,
  POLICY_NAME_PREFIX,
};
