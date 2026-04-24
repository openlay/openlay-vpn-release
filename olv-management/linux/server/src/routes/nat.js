const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
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

router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM nat_rules WHERE server_id = $1 ORDER BY wan_iface, name',
      [req.params.serverId]
    );
    res.json({ rules: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.get('/live', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const wanIface = req.query.wanIface;
    if (!wanIface) return res.status(400).json({ error: 'wanIface query param required' });
    const client = new AgentClient(parseInt(req.params.serverId));
    const out = await client.natListLive(wanIface);
    res.json(out);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/nat — agent-first flow with DB rollback.
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const b = req.body || {};
    // iOS APIClient encodes bodies as snake_case; accept both so older
    // camelCase callers keep working.
    const wanIface = b.wanIface ?? b.wan_iface;
    const srcCIDR = b.srcCIDR ?? b.src_cidr;
    const natTo = b.natTo ?? b.nat_to;
    if (!b.name) return res.status(400).json({ error: 'name is required' });
    if (!wanIface) return res.status(400).json({ error: 'wanIface is required' });
    if (!srcCIDR) return res.status(400).json({ error: 'srcCIDR is required' });

    const rule = {
      name: b.name,
      wanIface,
      srcCIDR,
      natTo: natTo || '',
      protocol: b.protocol || '',
      description: b.description || '',
      enabled: b.enabled === undefined ? true : !!b.enabled,
    };

    const client = new AgentClient(parseInt(req.params.serverId));
    const agentRule = await client.natAddRule(rule);

    try {
      const { rows } = await pool.query(
        `INSERT INTO nat_rules (server_id, name, wan_iface, src_cidr, nat_to, protocol, description, enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [req.params.serverId, rule.name, rule.wanIface, rule.srcCIDR,
         rule.natTo || null, rule.protocol || null, rule.description, rule.enabled]
      );
      res.status(201).json({ ...rows[0], agentId: agentRule.id });
    } catch (dbErr) {
      try { await client.natRemoveRule(agentRule.id); } catch {}
      if (dbErr.code === '23505') return res.status(409).json({ error: 'NAT rule name already exists on this server' });
      throw dbErr;
    }
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.put('/:ruleId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const existing = await pool.query(
      'SELECT * FROM nat_rules WHERE id = $1 AND server_id = $2',
      [req.params.ruleId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'NAT rule not found' });
    const row = existing.rows[0];

    const set = [];
    const vals = [];
    let idx = 1;
    const patch = {};
    const mapping = [
      ['wan_iface', 'wanIface'],
      ['src_cidr', 'srcCIDR'],
      ['nat_to', 'natTo'],
      ['protocol', 'protocol'],
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
      `UPDATE nat_rules SET ${set.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
      vals
    );

    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.natListRules();
      const match = (list.rules || []).find(r => r.name === row.name);
      if (match) await client.natUpdateRule(match.id, patch);
    } catch (err) {
      console.error(`[nat] agent sync failed:`, err.message);
    }
    res.json(rows[0]);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.delete('/:ruleId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const existing = await pool.query(
      'SELECT * FROM nat_rules WHERE id = $1 AND server_id = $2',
      [req.params.ruleId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'NAT rule not found' });
    const row = existing.rows[0];

    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.natListRules();
      const match = (list.rules || []).find(r => r.name === row.name);
      if (match) await client.natRemoveRule(match.id);
    } catch (err) {
      console.error(`[nat] agent delete failed (keeping DB change):`, err.message);
    }
    await pool.query('DELETE FROM nat_rules WHERE id = $1 AND server_id = $2',
      [req.params.ruleId, req.params.serverId]);
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
