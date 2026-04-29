// Re-push route_policies to the agent after a user's peer set changes.
//
// Triggered by /firewall/resync-users (called by app-api connect.js
// when a peer is added/removed). Designed for high-frequency reconnect:
// we skip work whenever the resolved (srcCIDR, ingressIface) didn't
// change vs. what's already on the agent. That makes the static-IP
// reconnect storm essentially free (lookup + string compare, no pf
// reload).
//
// State transitions handled (after diff check):
//   1. was empty   / now resolved  → ADD
//   2. was resolved / now empty    → REMOVE only (no pf rule = no match,
//      which is what we want when the typed ref can't be satisfied)
//   3. was IPa     / now IPb       → REMOVE + ADD
//   4. was X       / now X         → SKIP (the cheap path)
const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');
const { resolvePolicyIngress } = require('./targetResolvers');

/**
 * Find every route_policy on `serverId` whose ingress reference is
 * affected by changes to `userIds`. Push fresh resolution to agent.
 *
 * Single SQL for the affected-set query (was N+1 before). Sub-queries
 * cover all three typed sources:
 *   - ingress_type=users  → route_policy_users pivot
 *   - ingress_type=group  → user_group_members of ingress_group_id
 *   - ingress_type=device → devices.user_id of ingress_device_id
 */
async function resyncPoliciesByUsers(serverId, userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return { resynced: 0, skipped: 0 };
  const validUserIds = userIds.filter(Boolean);
  if (validUserIds.length === 0) return { resynced: 0, skipped: 0 };

  // One query gets every policy where typed ref intersects the user set.
  // EXISTS sub-queries short-circuit so it stays cheap even at high
  // policy counts.
  const { rows: affected } = await pool.query(
    `SELECT p.* FROM route_policies p
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
    [serverId, validUserIds]
  );
  if (affected.length === 0) return { resynced: 0, skipped: 0 };

  // List agent rules once. Lookup by name; compare srcCIDR + ingressIface
  // before deciding to mutate. Agent returns these fields in the policy
  // list (router state JSON), so the cheap "did anything actually
  // change?" check is just two string compares.
  const client = new AgentClient(serverId);
  const list = await client.routerListPolicies().catch(() => ({ policies: [] }));
  const byName = new Map((list.policies || []).map(p => [p.name, p]));
  let resynced = 0;
  let skipped = 0;
  for (const p of affected) {
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
      if (!onAgent && !hasMatch) {
        skipped++;
        continue;
      }

      if (onAgent) {
        await client.routerRemovePolicy(onAgent.id).catch(err => {
          console.error(`[policyResync] remove ${p.name} failed:`, err.message);
        });
      }
      if (hasMatch) {
        await client.routerAddPolicy({
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
        });
      }
      resynced++;
    } catch (err) {
      console.error(`[policyResync] policy ${p.id} ${p.name} failed:`, err.message);
    }
  }
  return { resynced, skipped };
}

module.exports = { resyncPoliciesByUsers };
