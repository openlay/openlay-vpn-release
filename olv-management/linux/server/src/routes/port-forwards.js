// Port forwards (DNAT / rdr rules). Exposed under a user-facing URL
// because admins shopping for a "port forward" screen won't grep for
// "rdr". The underlying agent commands are all rdrXxx.
const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const enterpriseContext = require('../middleware/enterpriseContext');
const { isAdmin } = require('../constants/roles');
const { requireAdmin } = require('../middleware/serverAccess');

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

router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM rdr_rules WHERE server_id = $1 ORDER BY wan_iface, external_port_start',
      [req.params.serverId]
    );
    res.json({ rules: rows });
  } catch (err) {
    sendError(res, err, req);
  }
});

router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const b = req.body || {};
    if (!b.name) return res.status(400).json({ error: 'name is required' });
    if (!b.wanIface) return res.status(400).json({ error: 'wanIface is required' });
    if (!b.externalPortStart) return res.status(400).json({ error: 'externalPortStart is required' });
    if (!b.protocol) return res.status(400).json({ error: 'protocol is required (tcp|udp|both)' });
    if (!b.internalIP) return res.status(400).json({ error: 'internalIP is required' });
    if (!b.internalPortStart) return res.status(400).json({ error: 'internalPortStart is required' });

    const rule = {
      name: b.name,
      wanIface: b.wanIface,
      externalIP: b.externalIP || '',
      externalPortStart: b.externalPortStart,
      externalPortEnd: b.externalPortEnd || 0,
      protocol: b.protocol,
      internalIP: b.internalIP,
      internalPortStart: b.internalPortStart,
      internalPortEnd: b.internalPortEnd || 0,
      autoOpenFirewall: b.autoOpenFirewall === undefined ? true : !!b.autoOpenFirewall,
      description: b.description || '',
      enabled: b.enabled === undefined ? true : !!b.enabled,
    };

    const client = new AgentClient(parseInt(req.params.serverId));
    const agentRule = await client.rdrAddRule(rule);

    try {
      const { rows } = await pool.query(
        `INSERT INTO rdr_rules (
           server_id, name, wan_iface, external_ip,
           external_port_start, external_port_end, protocol,
           internal_ip, internal_port_start, internal_port_end,
           auto_open_firewall, description, enabled
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
        [
          req.params.serverId, rule.name, rule.wanIface,
          rule.externalIP || null,
          rule.externalPortStart, rule.externalPortEnd || null,
          rule.protocol, rule.internalIP,
          rule.internalPortStart, rule.internalPortEnd || null,
          rule.autoOpenFirewall, rule.description, rule.enabled,
        ]
      );
      res.status(201).json({ ...rows[0], agentId: agentRule.id });
    } catch (dbErr) {
      try { await client.rdrRemoveRule(agentRule.id); } catch {}
      if (dbErr.code === '23505') return res.status(409).json({ error: 'Port-forward name already exists on this server' });
      throw dbErr;
    }
  } catch (err) {
    sendError(res, err, req);
  }
});

router.put('/:ruleId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const existing = await pool.query(
      'SELECT * FROM rdr_rules WHERE id = $1 AND server_id = $2',
      [req.params.ruleId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Port-forward not found' });
    const row = existing.rows[0];

    const set = [];
    const vals = [];
    let idx = 1;
    const patch = {};
    const mapping = [
      ['wan_iface', 'wanIface'],
      ['external_ip', 'externalIP'],
      ['external_port_start', 'externalPortStart'],
      ['external_port_end', 'externalPortEnd'],
      ['protocol', 'protocol'],
      ['internal_ip', 'internalIP'],
      ['internal_port_start', 'internalPortStart'],
      ['internal_port_end', 'internalPortEnd'],
      ['auto_open_firewall', 'autoOpenFirewall'],
      ['description', 'description'],
      ['enabled', 'enabled'],
    ];
    for (const [col, camel] of mapping) {
      if (req.body[camel] === undefined) continue;
      set.push(`${col} = $${idx++}`);
      vals.push(req.body[camel] === '' ? null : req.body[camel]);
      patch[camel] = req.body[camel];
    }
    if (set.length === 0) return res.status(400).json({ error: 'No fields to update' });
    set.push('updated_at = NOW()');
    vals.push(req.params.ruleId, req.params.serverId);
    const { rows } = await pool.query(
      `UPDATE rdr_rules SET ${set.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
      vals
    );

    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.rdrListRules();
      const match = (list.rules || []).find(r => r.name === row.name);
      if (match) await client.rdrUpdateRule(match.id, patch);
    } catch (err) {
      console.error(`[port-forwards] agent sync failed:`, err.message);
    }
    res.json(rows[0]);
  } catch (err) {
    sendError(res, err, req);
  }
});

router.delete('/:ruleId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const existing = await pool.query(
      'SELECT * FROM rdr_rules WHERE id = $1 AND server_id = $2',
      [req.params.ruleId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Port-forward not found' });
    const row = existing.rows[0];

    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.rdrListRules();
      const match = (list.rules || []).find(r => r.name === row.name);
      if (match) await client.rdrRemoveRule(match.id);
    } catch (err) {
      console.error(`[port-forwards] agent delete failed (keeping DB change):`, err.message);
    }
    await pool.query('DELETE FROM rdr_rules WHERE id = $1 AND server_id = $2',
      [req.params.ruleId, req.params.serverId]);
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
