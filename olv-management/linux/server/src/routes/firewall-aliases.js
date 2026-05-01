const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const { resyncRulesByAlias } = require('../services/ruleOrchestrator');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

async function verifyAccess(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT id, access_mode FROM servers WHERE id = $1', [serverId])
    : await pool.query('SELECT id, access_mode FROM servers WHERE id = $1 AND enterprise_id = $2', [serverId, req.enterpriseId]);
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  if (rows[0].access_mode === 'public' && !isRoot) throw Object.assign(new Error('Root required'), { status: 403 });
}

function requireAdmin(req, res) {
  if (!['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) {
    res.status(403).json({ error: 'Admin access required' });
    return false;
  }
  return true;
}

// GET /api/servers/:serverId/firewall/aliases
router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM firewall_aliases WHERE server_id = $1 ORDER BY name',
      [req.params.serverId]
    );
    res.json({ aliases: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/aliases
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { name, description, addresses } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    if (!addresses || !Array.isArray(addresses) || addresses.length === 0)
      return res.status(400).json({ error: 'addresses array is required' });
    const { rows } = await pool.query(
      'INSERT INTO firewall_aliases (server_id, name, description, addresses) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.serverId, name, description || '', addresses]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Alias name already exists' });
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PUT /api/servers/:serverId/firewall/aliases/:aliasId
router.put('/:aliasId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { name, description, addresses } = req.body;
    const fields = [];
    const values = [];
    let idx = 1;
    if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
    if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }
    if (addresses !== undefined) { fields.push(`addresses = $${idx++}`); values.push(addresses); }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push(`updated_at = NOW()`);
    values.push(req.params.aliasId, req.params.serverId);
    const { rows } = await pool.query(
      `UPDATE firewall_aliases SET ${fields.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
      values
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Alias not found' });
    // Resync rules when the addresses array changed so iptables reflects the new list.
    if (addresses !== undefined) {
      try { await resyncRulesByAlias(parseInt(req.params.serverId), parseInt(req.params.aliasId)); }
      catch (syncErr) { console.error(`[alias] resync failed:`, syncErr.message); }
    }
    res.json(rows[0]);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/firewall/aliases/:aliasId
router.delete('/:aliasId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    // Drop agent rules referencing this alias before DB delete to avoid orphans.
    await removeRulesReferencingAlias(parseInt(req.params.serverId), parseInt(req.params.aliasId));
    const { rowCount } = await pool.query(
      'DELETE FROM firewall_aliases WHERE id = $1 AND server_id = $2',
      [req.params.aliasId, req.params.serverId]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Alias not found' });
    // Defensive: even though removeRulesReferencingAlias already
    // walked & deleted, a stale rule pushed during a concurrent edit
    // could slip through. resyncRulesByAlias re-checks and rebuilds
    // any survivors with empty resolution → effectively a clean-up.
    try {
      const { resyncRulesByAlias } = require('../services/ruleOrchestrator');
      await resyncRulesByAlias(parseInt(req.params.serverId), parseInt(req.params.aliasId));
    } catch (err) {
      console.error(`[firewall-aliases/DELETE] resync after delete: ${err.message}`);
    }
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

async function removeRulesReferencingAlias(serverId, aliasId) {
  const client = new AgentClient(serverId);
  const all = await client.firewallListAllRules();
  const seen = new Set();
  for (const [iface, rules] of Object.entries(all.interfaces || {})) {
    for (const rule of rules) {
      if (!rule.groupId) continue;
      if (rule.srcAliasId != aliasId && rule.dstAliasId != aliasId) continue;
      const key = `${iface}::${rule.groupId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      try { await client.firewallRemoveGroup(iface, rule.groupId); } catch {}
    }
  }
}

module.exports = router;
