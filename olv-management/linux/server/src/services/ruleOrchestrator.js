const crypto = require('crypto');
const AgentClient = require('./agentClient');
const { resolveSide } = require('./ruleResolver');
const { pool } = require('../db/pool');

function generateGroupId() {
  return crypto.randomUUID();
}

/**
 * Create a logical rule on the agent — resolve zone/alias/user refs to IPs,
 * expand into N physical iptables rules sharing a groupId, return one logical rule.
 */
async function createLogicalRule(serverId, iface, body) {
  // iOS APIClient encodes with convertToSnakeCase, so accept both spellings.
  const {
    srcIP, dstIP, src_ip, dst_ip,
    srcZoneId, dstZoneId, src_zone_id, dst_zone_id,
    srcAliasId, dstAliasId, src_alias_id, dst_alias_id,
    srcUserId, dstUserId, src_user_id, dst_user_id,
    ...rest
  } = body;
  const side = {
    srcIP: srcIP ?? src_ip,
    dstIP: dstIP ?? dst_ip,
    srcZoneId: srcZoneId ?? src_zone_id,
    dstZoneId: dstZoneId ?? dst_zone_id,
    srcAliasId: srcAliasId ?? src_alias_id,
    dstAliasId: dstAliasId ?? dst_alias_id,
    srcUserId: srcUserId ?? src_user_id,
    dstUserId: dstUserId ?? dst_user_id,
  };

  const srcIPs = await resolveSide(serverId, { ip: side.srcIP, zoneId: side.srcZoneId, aliasId: side.srcAliasId, userId: side.srcUserId });
  const dstIPs = await resolveSide(serverId, { ip: side.dstIP, zoneId: side.dstZoneId, aliasId: side.dstAliasId, userId: side.dstUserId });

  // Guard: if a reference was provided but resolved to nothing, the rule would
  // silently match everything — fail fast instead.
  if ((side.srcZoneId || side.srcAliasId || side.srcUserId) && srcIPs.length === 0) {
    throw new Error('Source zone/alias/user resolved to no IPs');
  }
  if ((side.dstZoneId || side.dstAliasId || side.dstUserId) && dstIPs.length === 0) {
    throw new Error('Destination zone/alias/user resolved to no IPs');
  }

  const groupId = generateGroupId();
  const metadata = { groupId };
  if (side.srcZoneId != null) metadata.srcZoneId = side.srcZoneId;
  if (side.dstZoneId != null) metadata.dstZoneId = side.dstZoneId;
  if (side.srcAliasId != null) metadata.srcAliasId = side.srcAliasId;
  if (side.dstAliasId != null) metadata.dstAliasId = side.dstAliasId;
  if (side.srcUserId) metadata.srcUserId = side.srcUserId;
  if (side.dstUserId) metadata.dstUserId = side.dstUserId;

  const client = new AgentClient(serverId);
  const physical = [];
  for (const s of srcIPs) {
    for (const d of dstIPs) {
      const rule = { ...rest, ...metadata };
      if (s != null) rule.srcIP = s;
      if (d != null) rule.dstIP = d;
      const created = await client.firewallAddRule(iface, rule);
      physical.push(created);
    }
  }

  return buildLogicalRule(physical, { groupId, ...metadata, iface, ...rest });
}

/**
 * Delete a logical rule — remove all physical rules with the given groupId.
 * If the id is not a groupId (no group exists), fall back to single-rule delete.
 */
async function deleteLogicalRule(serverId, iface, ruleId) {
  const client = new AgentClient(serverId);
  const result = await client.firewallRemoveGroup(iface, ruleId);
  if (result.removed === 0) {
    return client.firewallRemoveRule(iface, ruleId);
  }
  return result;
}

/**
 * Group physical rules by groupId and collapse fields. Rules without groupId
 * are treated as standalone logical rules (single-member group).
 */
function groupPhysicalRules(rules) {
  const groups = new Map();
  for (const rule of rules) {
    const key = rule.groupId || `__single_${rule.id}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(rule);
  }
  const logical = [];
  for (const [key, members] of groups) {
    const first = members[0];
    logical.push(buildLogicalRule(members, first));
  }
  // Preserve ordering by newest createdAt
  logical.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  return logical;
}

function buildLogicalRule(members, base) {
  const first = members[0] || base;
  const hasGroup = !!base.groupId;
  const srcIPs = [...new Set(members.map(r => r.srcIP).filter(Boolean))];
  const dstIPs = [...new Set(members.map(r => r.dstIP).filter(Boolean))];
  return {
    id: hasGroup ? base.groupId : first.id,
    groupId: base.groupId || null,
    iface: first.iface || base.iface,
    label: first.label || base.label,
    target: first.target || base.target,
    protocol: first.protocol || base.protocol,
    srcPort: first.srcPort || base.srcPort,
    dstPort: first.dstPort || base.dstPort,
    log: first.log || base.log,
    system: first.system || base.system,
    createdAt: first.createdAt || base.createdAt,
    srcIP: srcIPs.length === 1 ? srcIPs[0] : (srcIPs[0] || null),
    dstIP: dstIPs.length === 1 ? dstIPs[0] : (dstIPs[0] || null),
    srcZoneId: first.srcZoneId ?? base.srcZoneId ?? null,
    dstZoneId: first.dstZoneId ?? base.dstZoneId ?? null,
    srcAliasId: first.srcAliasId ?? base.srcAliasId ?? null,
    dstAliasId: first.dstAliasId ?? base.dstAliasId ?? null,
    srcUserId: first.srcUserId ?? base.srcUserId ?? null,
    dstUserId: first.dstUserId ?? base.dstUserId ?? null,
    memberCount: members.length,
  };
}

/**
 * Find and rebuild every logical rule on this server whose srcZoneId or
 * dstZoneId matches. Used when zone membership changes.
 */
async function resyncRulesByZone(serverId, zoneId) {
  await resyncRulesWhere(serverId, r => r.srcZoneId == zoneId || r.dstZoneId == zoneId);
}

async function resyncRulesByAlias(serverId, aliasId) {
  await resyncRulesWhere(serverId, r => r.srcAliasId == aliasId || r.dstAliasId == aliasId);
}

async function resyncRulesByUsers(serverId, userIds) {
  const set = new Set(userIds.filter(Boolean));
  if (set.size === 0) return;
  await resyncRulesWhere(serverId, r => set.has(r.srcUserId) || set.has(r.dstUserId));
  // Built-in zone "vpn-peers" resolves to all peer IPs — rebuild anything
  // that references it too, since peer changes alter its membership.
  const { rows } = await pool.query(
    'SELECT id FROM firewall_zones WHERE server_id = $1 AND name = $2',
    [serverId, 'vpn-peers']
  );
  if (rows.length > 0) {
    await resyncRulesByZone(serverId, rows[0].id);
  }
}

async function resyncRulesWhere(serverId, predicate) {
  const client = new AgentClient(serverId);
  const all = await client.firewallListAllRules();
  const byIface = all.interfaces || {};

  const affectedGroups = new Map();
  for (const [iface, rules] of Object.entries(byIface)) {
    for (const rule of rules) {
      if (!rule.groupId) continue;
      if (!predicate(rule)) continue;
      const key = `${iface}::${rule.groupId}`;
      if (!affectedGroups.has(key)) affectedGroups.set(key, { iface, rule });
    }
  }

  for (const { iface, rule } of affectedGroups.values()) {
    const body = {
      srcZoneId: rule.srcZoneId,
      dstZoneId: rule.dstZoneId,
      srcAliasId: rule.srcAliasId,
      dstAliasId: rule.dstAliasId,
      srcUserId: rule.srcUserId,
      dstUserId: rule.dstUserId,
      srcIP: rule.srcIP && !rule.srcZoneId && !rule.srcAliasId && !rule.srcUserId ? rule.srcIP : undefined,
      dstIP: rule.dstIP && !rule.dstZoneId && !rule.dstAliasId && !rule.dstUserId ? rule.dstIP : undefined,
      label: rule.label,
      target: rule.target,
      protocol: rule.protocol,
      srcPort: rule.srcPort,
      dstPort: rule.dstPort,
      log: rule.log,
    };
    try {
      await client.firewallRemoveGroup(iface, rule.groupId);
      await createLogicalRule(serverId, iface, body);
    } catch (err) {
      console.error(`[ruleOrchestrator] resync failed for group ${rule.groupId}:`, err.message);
    }
  }
}

module.exports = {
  createLogicalRule,
  deleteLogicalRule,
  groupPhysicalRules,
  resyncRulesByZone,
  resyncRulesByAlias,
  resyncRulesByUsers,
};
