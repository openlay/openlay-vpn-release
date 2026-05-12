// Re-push route_policies to the agent after a user / peer / group /
// device change. Two layers:
//
//   resyncPoliciesByIds(serverId, policyIds, removedNames)
//      Primitive — refresh specific policies on agent. Each id is
//      re-resolved + remove+add'd (with diff-skip when nothing
//      changed). Each `removedNames` entry is force-removed from
//      agent (used by callers handling CASCADE-deleted policies, where
//      the DB row is gone but agent still has a stale pf rule).
//
//   resyncPoliciesByUsers(serverId, userIds)
//      Convenience for the /api/connect IP-change path. Builds the
//      policy-id list by intersecting current pivot/group/device
//      membership with userIds, then delegates to ByIds.
//
// IMPORTANT for delete paths: the pivot/membership rows usually CASCADE
// before the resync runs. resyncPoliciesByUsers's query won't find them
// then. Delete handlers must SNAPSHOT affected policy ids BEFORE the
// DELETE and call resyncPoliciesByIds directly.
const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');
const { resolvePolicyIngress } = require('./targetResolvers');
const { withServerLock } = require('./serverLock');

function buildAgentPayload(p, resolved) {
  return {
    name: p.name,
    priority: p.priority,
    ingressIface: resolved.ingressIface,
    srcCIDR: resolved.srcCIDR,
    dstCIDR: p.dst_cidr || '',
    protocol: p.protocol || '',
    dstPortStart: p.dst_port_start || 0,
    dstPortEnd: p.dst_port_end || 0,
    fib: p.fib,
    action: p.action,
    gateway: p.gateway || '',
    gatewayIface: p.gateway_iface,
    description: p.description || '',
    enabled: p.enabled,
  };
}

async function resyncPoliciesByIds(serverId, policyIds = [], removedNames = []) {
  const ids = (policyIds || []).filter(Boolean);
  const removed = (removedNames || []).filter(Boolean);
  if (ids.length === 0 && removed.length === 0) return { resynced: 0, skipped: 0, removed: 0 };
  return withServerLock(serverId, () => resyncPoliciesByIdsLocked(serverId, ids, removed));
}

async function resyncPoliciesByIdsLocked(serverId, ids, removed) {
  const client = new AgentClient(serverId);
  const list = await client.routerListPolicies().catch(() => ({ policies: [] }));
  const byName = new Map((list.policies || []).map(p => [p.name, p]));

  // Hard removes — for policies CASCADE-deleted from DB. Their agent
  // rule must go too, otherwise we leak stale pf state with no
  // back-reference.
  let removedCount = 0;
  for (const name of removed) {
    const onAgent = byName.get(name);
    if (!onAgent) continue;
    try {
      await client.routerRemovePolicy(onAgent.id);
      byName.delete(name);
      removedCount++;
    } catch (err) {
      console.error(`[policyResync] hard-remove ${name} failed:`, err.message);
    }
  }

  if (ids.length === 0) return { resynced: 0, skipped: 0, removed: removedCount };

  // Refresh — pull DB rows by id, re-resolve, diff-skip, remove+add.
  const { rows } = await pool.query(
    'SELECT * FROM route_policies WHERE id = ANY($1::int[]) AND server_id = $2',
    [ids, serverId]
  );
  let resynced = 0;
  let skipped = 0;
  for (const p of rows) {
    try {
      const resolved = await resolvePolicyIngress(p, serverId);
      const onAgent = byName.get(p.name);
      const hasMatch = resolved.resolvedIPs.length > 0 || p.ingress_type === 'custom';

      // Cheap path: state on agent already matches resolved view.
      if (onAgent && hasMatch
          && (onAgent.srcCIDR ?? '')      === (resolved.srcCIDR ?? '')
          && (onAgent.ingressIface ?? '') === (resolved.ingressIface ?? '')) {
        skipped++;
        continue;
      }
      // Cheap path: not on agent and shouldn't be (still empty).
      if (!onAgent && !hasMatch) { skipped++; continue; }

      if (onAgent) {
        await client.routerRemovePolicy(onAgent.id).catch(err => {
          console.error(`[policyResync] remove ${p.name} failed:`, err.message);
        });
      }
      if (hasMatch) {
        await client.routerAddPolicy(buildAgentPayload(p, resolved));
      }
      resynced++;
    } catch (err) {
      console.error(`[policyResync] policy ${p.id} ${p.name} failed:`, err.message);
    }
  }
  return { resynced, skipped, removed: removedCount };
}

/**
 * Convenience for /api/connect peer-change path. Finds policies where
 * any of the userIds currently intersects ingress_type users/group/
 * device, then refreshes those.
 *
 * Caveat: relies on CURRENT membership state. Don't call this from
 * delete-cascade paths — the rows are already gone, so the EXISTS
 * sub-queries return false and you'll miss policies you wanted to
 * resync. For those, snapshot policy ids BEFORE the cascade and use
 * resyncPoliciesByIds directly.
 */
async function resyncPoliciesByUsers(serverId, userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return { resynced: 0, skipped: 0, removed: 0 };
  const valid = userIds.filter(Boolean);
  if (valid.length === 0) return { resynced: 0, skipped: 0, removed: 0 };

  const { rows: affected } = await pool.query(
    `SELECT p.id FROM route_policies p
      WHERE p.server_id = $1
        AND p.ingress_type IN ('users','group','device')
        AND (
          (p.ingress_type = 'users' AND EXISTS (
             SELECT 1 FROM route_policy_users rpu
              WHERE rpu.policy_id = p.id AND rpu.user_id = ANY($2::text[])
          ))
          OR
          (p.ingress_type = 'group' AND EXISTS (
             SELECT 1 FROM user_group_members ugm
              WHERE ugm.user_group_id = p.ingress_group_id AND ugm.user_id = ANY($2::text[])
          ))
          OR
          (p.ingress_type = 'device' AND EXISTS (
             SELECT 1 FROM devices d
              WHERE d.id = p.ingress_device_id AND d.user_id = ANY($2::text[])
          ))
        )`,
    [serverId, valid]
  );
  return resyncPoliciesByIds(serverId, affected.map(r => r.id));
}

module.exports = { resyncPoliciesByIds, resyncPoliciesByUsers };
