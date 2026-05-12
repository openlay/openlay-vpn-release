// Auto-manage firewall ACCEPT rules for Application Servers.
//
// An app server declares: granted users (ACL) → may reach app target on
// `app.port`. For that traffic to actually pass through the agent's pf,
// we push physical ACCEPT rules: srcIP=<granted user's peer IP> →
// dstIP=<resolved target> dstPort=app.port proto=tcp.
//
// Rules are pushed under `groupId = "app-<id>"` so we tear down + rebuild
// en masse when the app changes (CRUD, ACL change, target user/device IP
// change, group membership change).
//
// Edge cases:
//   - ACL empty + enabled → no users granted → no rules
//   - target offline (user/device peer not connected) → no dst IP → no rules
//   - app disabled → no rules
//   - granted user offline → that user contributes 0 rules; others still added
//
// Triggers (wired by callers):
//   - POST/PUT/DELETE on /application-servers
//   - resyncRulesByUsers chain (peer IP changes)
//   - user-groups POST/DELETE members (group membership for group-ACL apps)
const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');
const {
  resolveAppServerTarget,
  resolveUserPeerOnServer,
} = require('./targetResolvers');
const { withServerLock } = require('./serverLock');

// Rules pushed under this prefix are managed exclusively by this
// service — admin must NOT edit/delete them via the firewall UI, since
// the next sync (CRUD or peer change) would silently overwrite their
// edits. firewall.js uses this prefix to refuse direct DELETE/PUT on
// these rules and recommend the Application Server form instead.
const APP_RULE_PRIORITY = 1500;  // above user band (100-999), into system reserved
const APP_RULE_LABEL_PREFIX = 'app-server-';
const APP_RULE_GROUP_PREFIX = 'app-';

// groupId stays numeric+stable — survives admin renames so tear-down
// matches existing agent rules. Label is human-readable for the
// firewall list view; rebuilt from app.name on every sync so renames
// propagate.
function groupIdFor(appId)  { return `${APP_RULE_GROUP_PREFIX}${appId}`; }

/**
 * Sanitize an app's name for inclusion in a pf label. pf accepts the
 * label as a quoted string but the firewall list / iOS row treats it
 * as a single token, so collapse whitespace and strip anything outside
 * [A-Za-z0-9_-]. Falls back to the id when name has no usable chars.
 */
function labelFor(appId, appName) {
  const safe = (appName || '')
    .normalize('NFKD')
    .replace(/[^A-Za-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return safe ? `${APP_RULE_LABEL_PREFIX}${appId}-${safe}`
              : `${APP_RULE_LABEL_PREFIX}${appId}`;
}

function isAppManagedGroupId(groupId) {
  return typeof groupId === 'string' && groupId.startsWith(APP_RULE_GROUP_PREFIX);
}

/**
 * Resolve the union ACL of an app server: direct user_ids ∪ group
 * member user_ids. Returns array of distinct user_ids.
 */
async function resolveAclUsers(appId) {
  const { rows } = await pool.query(
    `SELECT user_id FROM application_server_users WHERE app_id = $1
     UNION
     SELECT m.user_id
       FROM application_server_groups g
       JOIN user_group_members m ON m.user_group_id = g.user_group_id
      WHERE g.app_id = $1`,
    [appId]
  );
  return rows.map(r => r.user_id);
}

/**
 * Remove every agent firewall rule belonging to this app server. Walks
 * all ifaces returned by the agent so we don't leave orphans behind.
 * Idempotent — safe to call when nothing exists.
 *
 * Uses replaceGroup(iface, groupId, []) per iface so each (iface,
 * groupId) tear-down is atomic at the agent. A WS timeout either commits
 * the empty-state or leaves the prior rules — never a partial state.
 */
async function removeAppServerRules(serverId, appId) {
  const client = new AgentClient(serverId);
  const all = await client.firewallListAllRules().catch(() => ({ interfaces: {} }));
  const groupId = groupIdFor(appId);
  let removed = 0;
  for (const iface of Object.keys(all.interfaces || {})) {
    try {
      const r = await client.firewallReplaceGroup(iface, groupId, []);
      removed += r?.removed || 0;
    } catch (err) {
      console.error(`[appServerFirewall] remove ${groupId} on ${iface} failed:`, err.message);
    }
  }
  return removed;
}

/**
 * Sync the firewall rule set for one app server. Idempotent. Tears down
 * the existing groupId and rebuilds based on current DB + peer state.
 *
 * Wrapped in withServerLock so the remove→add window can't interleave with
 * another sync of the same server (which would either lose this sync's
 * adds — last-write-wins on a stable groupId — or, worse, leave a partial
 * rule set if the racing sync's remove fires between this sync's adds).
 */
async function syncAppServerFirewall(appId) {
  const { rows } = await pool.query(
    'SELECT * FROM application_servers WHERE id = $1',
    [appId]
  );
  const app = rows[0];
  if (!app) return { removed: 0, added: 0, reason: 'not-found' };
  return withServerLock(app.server_id, () => syncAppServerFirewallLocked(app, appId));
}

async function syncAppServerFirewallLocked(app, appId) {
  const groupId = groupIdFor(appId);
  const client = new AgentClient(app.server_id);

  // Snapshot the agent's current interface set so we can tear down rules
  // on ifaces that no longer hold this app (user migrated to a different
  // iface, agent gained a new wg interface, etc.).
  const all = await client.firewallListAllRules().catch(() => ({ interfaces: {} }));
  const knownIfaces = new Set(Object.keys(all.interfaces || {}));

  // Early-exit cases: no rules should exist anywhere for this app.
  // Atomically clear every iface in one replaceGroup-with-empty per iface.
  const teardownAll = async (reason) => {
    let removed = 0;
    for (const iface of knownIfaces) {
      try {
        const r = await client.firewallReplaceGroup(iface, groupId, []);
        removed += r?.removed || 0;
      } catch (err) {
        console.error(`[appServerFirewall] teardown ${groupId} on ${iface} failed:`, err.message);
      }
    }
    return { removed, added: 0, reason };
  };

  if (!app.enabled) return teardownAll('disabled');

  const target = await resolveAppServerTarget(app, app.server_id);
  if (!target.ip) return teardownAll('target-offline');

  const aclUserIds = await resolveAclUsers(appId);
  if (aclUserIds.length === 0) return teardownAll('empty-acl');

  // protocol may be 'tcp', 'udp', or 'tcp+udp'. One physical rule per
  // (granted user, protocol), grouped by the user's peer iface so each
  // iface's replaceGroup is atomic.
  const protos = (app.protocol || 'tcp') === 'tcp+udp' ? ['tcp', 'udp'] : [app.protocol || 'tcp'];
  const label = labelFor(appId, app.name);
  const rulesByIface = new Map(); // iface → Rule[]

  for (const uid of aclUserIds) {
    const peer = await resolveUserPeerOnServer(app.server_id, uid);
    if (!peer) continue;
    if (!rulesByIface.has(peer.iface)) rulesByIface.set(peer.iface, []);
    for (const proto of protos) {
      rulesByIface.get(peer.iface).push({
        groupId,
        srcIP: `${peer.ip}/32`,
        dstIP: `${target.ip}/32`,
        protocol: proto,
        dstPort: `${app.port}`,
        target: 'ACCEPT',
        label,
        priority: APP_RULE_PRIORITY,
      });
    }
  }

  // Touch every iface that EITHER had old rules OR has new ones. The
  // union covers two cases: a user moving from iface A → B (replaceGroup
  // on A with [] clears A; on B with the new rule adds it).
  const touchIfaces = new Set([...knownIfaces, ...rulesByIface.keys()]);
  let removed = 0;
  let added = 0;
  for (const iface of touchIfaces) {
    const rules = rulesByIface.get(iface) || [];
    try {
      const r = await client.firewallReplaceGroup(iface, groupId, rules);
      removed += r?.removed || 0;
      added += r?.added || 0;
    } catch (err) {
      console.error(`[appServerFirewall] replaceGroup ${groupId} on ${iface} failed:`, err.message);
    }
  }
  return { removed, added, reason: 'synced' };
}

/**
 * Sync every app server on a given server that involves any of these
 * users — either granting (ACL) or being targeted. Used as the chain
 * point from peer connect/disconnect.
 */
async function syncAppServersForUsers(serverId, userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return;
  const valid = userIds.filter(Boolean);
  if (valid.length === 0) return;
  const { rows } = await pool.query(
    `SELECT DISTINCT a.id FROM application_servers a
      WHERE a.server_id = $1
        AND (
          a.target_user_id = ANY($2::text[])
          OR EXISTS (
             SELECT 1 FROM devices d
              WHERE d.id = a.target_device_id AND d.user_id = ANY($2::text[])
          )
          OR EXISTS (
             SELECT 1 FROM application_server_users u
              WHERE u.app_id = a.id AND u.user_id = ANY($2::text[])
          )
          OR EXISTS (
             SELECT 1 FROM application_server_groups g
              JOIN user_group_members m ON m.user_group_id = g.user_group_id
              WHERE g.app_id = a.id AND m.user_id = ANY($2::text[])
          )
        )`,
    [serverId, valid]
  );
  for (const r of rows) {
    try { await syncAppServerFirewall(r.id); }
    catch (err) { console.error(`[appServerFirewall] sync app ${r.id} failed:`, err.message); }
  }
}

/**
 * Sync every app server on any server that has the given group in its
 * ACL. Used by user-groups membership change hook.
 */
async function syncAppServersForGroup(groupId) {
  const { rows } = await pool.query(
    `SELECT app_id, a.server_id
       FROM application_server_groups g
       JOIN application_servers a ON a.id = g.app_id
      WHERE g.user_group_id = $1`,
    [groupId]
  );
  for (const r of rows) {
    try { await syncAppServerFirewall(r.app_id); }
    catch (err) { console.error(`[appServerFirewall] group sync app ${r.app_id} failed:`, err.message); }
  }
}

module.exports = {
  syncAppServerFirewall,
  removeAppServerRules,
  syncAppServersForUsers,
  syncAppServersForGroup,
  isAppManagedGroupId,
  APP_RULE_GROUP_PREFIX,
  APP_RULE_LABEL_PREFIX,
};
