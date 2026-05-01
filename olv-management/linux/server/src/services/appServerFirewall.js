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
 */
async function removeAppServerRules(serverId, appId) {
  const client = new AgentClient(serverId);
  const all = await client.firewallListAllRules().catch(() => ({ interfaces: {} }));
  const groupId = groupIdFor(appId);
  let removed = 0;
  for (const iface of Object.keys(all.interfaces || {})) {
    try {
      const r = await client.firewallRemoveGroup(iface, groupId);
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
 */
async function syncAppServerFirewall(appId) {
  const { rows } = await pool.query(
    'SELECT * FROM application_servers WHERE id = $1',
    [appId]
  );
  const app = rows[0];
  if (!app) return { removed: 0, added: 0, reason: 'not-found' };

  const removed = await removeAppServerRules(app.server_id, appId);

  if (!app.enabled) return { removed, added: 0, reason: 'disabled' };

  // Resolve target → concrete IP. If target is user/device and offline,
  // skip — rules will get pushed once the target peer comes online via
  // the resyncRulesByUsers chain.
  const target = await resolveAppServerTarget(app, app.server_id);
  if (!target.ip) return { removed, added: 0, reason: 'target-offline' };

  // Resolve ACL → list of user_ids. Empty ACL = no rules (admin
  // explicitly granted nobody, so nobody should be allowed in).
  const aclUserIds = await resolveAclUsers(appId);
  if (aclUserIds.length === 0) return { removed, added: 0, reason: 'empty-acl' };

  // protocol may be 'tcp', 'udp', or 'tcp+udp'. Push one physical rule
  // per (granted user, protocol) — cross-product. All share the
  // app's groupId so a future tear-down hits everything.
  const protos = (app.protocol || 'tcp') === 'tcp+udp' ? ['tcp', 'udp'] : [app.protocol || 'tcp'];

  // Map each granted user to (iface, ip). Multiple users may sit on the
  // same iface; cross-iface is supported (one rule per (srcIP, iface)).
  const client = new AgentClient(app.server_id);
  let added = 0;
  for (const uid of aclUserIds) {
    const peer = await resolveUserPeerOnServer(app.server_id, uid);
    if (!peer) continue;     // user offline — skip
    for (const proto of protos) {
      try {
        await client.firewallAddRule(peer.iface, {
          groupId: groupIdFor(appId),
          srcIP: `${peer.ip}/32`,
          dstIP: `${target.ip}/32`,
          protocol: proto,
          dstPort: `${app.port}`,
          target: 'ACCEPT',
          label: labelFor(appId, app.name),
          priority: APP_RULE_PRIORITY,
        });
        added++;
      } catch (err) {
        console.error(`[appServerFirewall] add rule for app=${appId} src=${peer.ip} proto=${proto} failed:`, err.message);
      }
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
