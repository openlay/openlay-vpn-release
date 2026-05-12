// Auto-manage a single ACCEPT firewall rule per device whose Device
// Profile has `allow_wan_access = TRUE`.
//
// Shape of the pushed rule:
//   srcIP            = <device peer IP>/32   (resolved per-server)
//   dstIP            = 0.0.0.0/0              (matches the "wan" zone semantic)
//   dstZoneId        = <wan zone id>          (metadata for resync; agent stores)
//   dstExcludeCIDRs  = <VPN subnets>          (so "wan" means "everywhere except VPN")
//   target           = ACCEPT
//   priority         = 1400                   (1000+ band: defaults/auto-services)
//   groupId          = wan-access-<deviceId>  (stable; same across servers)
//   label            = wan-access-<deviceId>
//
// Triggers (wired by callers):
//   - PUT /api/admin/device-profiles/:id when allow_wan_access is in the body
//   - PUT /api/admin/devices/:id when profile_id changes
//   - resyncRulesByUsers chain (peer connect/disconnect, device delete, etc.)
//   - DELETE /api/admin/devices/:id (orphan cleanup, mirrors appServerFirewall)
//
// Edge cases:
//   - device disabled or pending  -> no rule
//   - profile_id NULL              -> no rule
//   - allow_wan_access FALSE       -> no rule
//   - device offline (no peer row) -> no rule pushed; next peer connect re-runs sync
//   - server has no `wan` zone     -> no rule (shouldn't happen; wan is built-in)

const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');
const { resolveDevicePeerOnServer } = require('./targetResolvers');
const { withServerLock } = require('./serverLock');

const WAN_RULE_PRIORITY = 1400;
const WAN_RULE_GROUP_PREFIX = 'wan-access-';
const WAN_RULE_LABEL_PREFIX = 'wan-access-';

function groupIdFor(deviceId) { return `${WAN_RULE_GROUP_PREFIX}${deviceId}`; }
function labelFor(deviceId)   { return `${WAN_RULE_LABEL_PREFIX}${deviceId}`; }

function isWanAccessManagedGroupId(groupId) {
  return typeof groupId === 'string' && groupId.startsWith(WAN_RULE_GROUP_PREFIX);
}

/**
 * Remove every wan-access rule for this device on this server (across
 * all ifaces). Idempotent. Uses replaceGroup(iface, groupId, []) per
 * iface so each tear-down is atomic at the agent.
 */
async function removeDeviceWanAccessRules(serverId, deviceId) {
  const client = new AgentClient(serverId);
  const all = await client.firewallListAllRules().catch(() => ({ interfaces: {} }));
  const groupId = groupIdFor(deviceId);
  let removed = 0;
  for (const iface of Object.keys(all.interfaces || {})) {
    try {
      const r = await client.firewallReplaceGroup(iface, groupId, []);
      removed += r?.removed || 0;
    } catch (err) {
      console.error(`[deviceWanAccessFirewall] remove ${groupId} on ${iface} failed:`, err.message);
    }
  }
  return removed;
}

/**
 * Tear down then (re)build the wan-access rule for one device on one
 * server. Idempotent — safe to call regardless of current state.
 */
async function syncDeviceWanAccessOnServer(serverId, deviceId) {
  return withServerLock(serverId, () => syncDeviceWanAccessOnServerLocked(serverId, deviceId));
}

async function syncDeviceWanAccessOnServerLocked(serverId, deviceId) {
  const { rows } = await pool.query(
    `SELECT d.status, d.profile_id, p.allow_wan_access
       FROM devices d
       LEFT JOIN device_profiles p ON p.id = d.profile_id
      WHERE d.id = $1`,
    [deviceId]
  );
  const dev = rows[0];
  const groupId = groupIdFor(deviceId);

  // Decide whether ANY rule should exist; if not, the only thing to do
  // is clear every iface that currently has one (handled below).
  let target = null;
  if (dev && dev.status === 'enabled' && dev.profile_id && dev.allow_wan_access) {
    const peer = await resolveDevicePeerOnServer(serverId, deviceId);
    if (peer) {
      const { rows: zoneRows } = await pool.query(
        `SELECT id FROM firewall_zones WHERE server_id = $1 AND name = 'wan'`,
        [serverId]
      );
      if (zoneRows.length > 0) {
        const { rows: subs } = await pool.query(
          'SELECT DISTINCT cidr FROM subnets WHERE server_id = $1',
          [serverId]
        );
        target = {
          iface: peer.iface,
          rule: {
            groupId,
            srcIP: `${peer.ip}/32`,
            dstIP: '0.0.0.0/0',
            dstZoneId: zoneRows[0].id,
            dstExcludeCIDRs: [...new Set(subs.map(r => r.cidr).filter(Boolean))],
            target: 'ACCEPT',
            label: labelFor(deviceId),
            priority: WAN_RULE_PRIORITY,
          },
        };
      }
    }
  }

  // One replaceGroup per touched iface — covers both clearing stale
  // ifaces and installing the new rule, atomically each.
  const client = new AgentClient(serverId);
  const all = await client.firewallListAllRules().catch(() => ({ interfaces: {} }));
  const knownIfaces = new Set(Object.keys(all.interfaces || {}));
  const touchIfaces = new Set(knownIfaces);
  if (target) touchIfaces.add(target.iface);

  let removed = 0;
  let added = 0;
  for (const iface of touchIfaces) {
    const rules = target && iface === target.iface ? [target.rule] : [];
    try {
      const r = await client.firewallReplaceGroup(iface, groupId, rules);
      removed += r?.removed || 0;
      added += r?.added || 0;
    } catch (err) {
      console.error(`[deviceWanAccessFirewall] replaceGroup ${groupId} on ${iface} failed:`, err.message);
    }
  }

  if (!dev) return { removed, added, reason: 'device-not-found' };
  if (dev.status !== 'enabled') return { removed, added, reason: 'device-not-enabled' };
  if (!dev.profile_id) return { removed, added, reason: 'no-profile' };
  if (!dev.allow_wan_access) return { removed, added, reason: 'wan-access-off' };
  if (!target) return { removed, added, reason: target === null ? 'peer-or-zone-missing' : 'synced' };
  return { removed, added, reason: 'synced' };
}

/**
 * Sync this device on every server it has (or had) a peer on. Used when
 * the device's profile assignment or its profile's allow_wan_access flag
 * changes — we don't know which server holds rules unless we look.
 */
async function syncDeviceWanAccessAcrossServers(deviceId) {
  const { rows } = await pool.query(
    'SELECT DISTINCT server_id FROM peers_meta WHERE device_id = $1',
    [deviceId]
  );
  for (const r of rows) {
    try { await syncDeviceWanAccessOnServer(r.server_id, deviceId); }
    catch (err) {
      console.error(`[deviceWanAccessFirewall] sync device=${deviceId} server=${r.server_id}: ${err.message}`);
    }
  }
}

/**
 * Sync every device assigned to this profile, across every server each
 * device has a peer on. Triggered when the profile's allow_wan_access
 * toggle flips.
 */
async function syncProfileWanAccessAcrossServers(profileId) {
  const { rows } = await pool.query(
    'SELECT id FROM devices WHERE profile_id = $1',
    [profileId]
  );
  for (const r of rows) {
    try { await syncDeviceWanAccessAcrossServers(r.id); }
    catch (err) {
      console.error(`[deviceWanAccessFirewall] profile sync device=${r.id}: ${err.message}`);
    }
  }
}

/**
 * Chain entry from resyncRulesByUsers — fire-and-forget sync for every
 * device owned by any of the given users on the given server. Cheap when
 * none of the users have wan-access devices (just an empty SELECT loop).
 */
async function syncWanAccessForUsers(serverId, userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return;
  const valid = userIds.filter(Boolean);
  if (valid.length === 0) return;
  const { rows } = await pool.query(
    'SELECT id FROM devices WHERE user_id = ANY($1::text[])',
    [valid]
  );
  for (const r of rows) {
    try { await syncDeviceWanAccessOnServer(serverId, r.id); }
    catch (err) {
      console.error(`[deviceWanAccessFirewall] user-chain sync device=${r.id}: ${err.message}`);
    }
  }
}

module.exports = {
  groupIdFor,
  isWanAccessManagedGroupId,
  removeDeviceWanAccessRules,
  syncDeviceWanAccessOnServer,
  syncDeviceWanAccessAcrossServers,
  syncProfileWanAccessAcrossServers,
  syncWanAccessForUsers,
  WAN_RULE_GROUP_PREFIX,
  WAN_RULE_LABEL_PREFIX,
};
