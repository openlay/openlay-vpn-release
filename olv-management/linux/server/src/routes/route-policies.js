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

// GET /api/servers/:serverId/route-policies — list all policies.
router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM route_policies WHERE server_id = $1 ORDER BY priority, id',
      [req.params.serverId]
    );
    res.json({ policies: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/route-policies/fib — ask the agent what
// FIB topology the kernel has. UI uses this to populate a FIB picker
// and to surface "reboot required" when loader.conf changed.
router.get('/fib', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const client = new AgentClient(parseInt(req.params.serverId));
    const info = await client.routerGetFibInfo();
    res.json(info);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/route-policies/live — pfctl -sr output.
router.get('/live', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const client = new AgentClient(parseInt(req.params.serverId));
    const out = await client.routerListLivePolicies();
    res.json(out);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/route-policies — create policy.
// Agent-first flow, same rollback shape as M1 routes: apply to agent
// (validates FIB + renders pf anchor), then write DB. If DB insert
// fails we compensate by deleting the agent-side policy.
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const b = req.body || {};
    if (!b.name) return res.status(400).json({ error: 'name is required' });
    if (!b.gatewayIface) return res.status(400).json({ error: 'gatewayIface is required' });

    const policyPayload = {
      name: b.name,
      priority: b.priority || 100,
      ingressIface: b.ingressIface || '',
      srcCIDR: b.srcCIDR || '',
      dstCIDR: b.dstCIDR || '',
      protocol: b.protocol || '',
      dstPortStart: b.dstPortStart || 0,
      dstPortEnd: b.dstPortEnd || 0,
      fib: b.fib || 0,
      action: b.action || 'route-to',
      gatewayIface: b.gatewayIface,
      gateway: b.gateway || '',
      description: b.description || '',
      enabled: b.enabled === undefined ? true : !!b.enabled,
    };

    const client = new AgentClient(parseInt(req.params.serverId));
    const agentPolicy = await client.routerAddPolicy(policyPayload);

    try {
      const { rows } = await pool.query(
        `INSERT INTO route_policies (
           server_id, name, priority, ingress_iface, src_cidr, dst_cidr,
           protocol, dst_port_start, dst_port_end, fib, action,
           gateway, gateway_iface, description, enabled
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         RETURNING *`,
        [
          req.params.serverId, b.name, policyPayload.priority,
          policyPayload.ingressIface || null,
          policyPayload.srcCIDR || null,
          policyPayload.dstCIDR || null,
          policyPayload.protocol || null,
          policyPayload.dstPortStart || null,
          policyPayload.dstPortEnd || null,
          policyPayload.fib, policyPayload.action,
          policyPayload.gateway || null,
          policyPayload.gatewayIface,
          policyPayload.description, policyPayload.enabled,
        ]
      );
      res.status(201).json({ ...rows[0], agentId: agentPolicy.id });
    } catch (dbErr) {
      try { await client.routerRemovePolicy(agentPolicy.id); } catch {}
      if (dbErr.code === '23505') return res.status(409).json({ error: 'Policy name already exists on this server' });
      throw dbErr;
    }
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PUT /api/servers/:serverId/route-policies/:id — partial update.
router.put('/:policyId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const existing = await pool.query(
      'SELECT * FROM route_policies WHERE id = $1 AND server_id = $2',
      [req.params.policyId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });
    const row = existing.rows[0];

    const setFields = [];
    const values = [];
    let idx = 1;
    const agentPatch = {};
    const mapping = [
      ['priority', 'priority'],
      ['ingress_iface', 'ingressIface'],
      ['src_cidr', 'srcCIDR'],
      ['dst_cidr', 'dstCIDR'],
      ['protocol', 'protocol'],
      ['dst_port_start', 'dstPortStart'],
      ['dst_port_end', 'dstPortEnd'],
      ['fib', 'fib'],
      ['action', 'action'],
      ['gateway', 'gateway'],
      ['gateway_iface', 'gatewayIface'],
      ['description', 'description'],
      ['enabled', 'enabled'],
    ];
    for (const [col, camel] of mapping) {
      if (req.body[camel] === undefined) continue;
      setFields.push(`${col} = $${idx++}`);
      values.push(req.body[camel]);
      agentPatch[camel] = req.body[camel];
    }
    if (setFields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    setFields.push('updated_at = NOW()');
    values.push(req.params.policyId, req.params.serverId);
    const { rows } = await pool.query(
      `UPDATE route_policies SET ${setFields.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
      values
    );

    // Re-sync to agent. DB → agent mismatch surfaces as a log line;
    // the DB stays authoritative and RestorePolicies on next boot
    // converges.
    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.routerListPolicies();
      const match = (list.policies || []).find(p => p.name === row.name);
      if (match) await client.routerUpdatePolicy(match.id, agentPatch);
    } catch (err) {
      console.error(`[route-policies] agent sync failed:`, err.message);
    }
    res.json(rows[0]);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/route-policies/:id
router.delete('/:policyId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const existing = await pool.query(
      'SELECT * FROM route_policies WHERE id = $1 AND server_id = $2',
      [req.params.policyId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Policy not found' });
    const row = existing.rows[0];

    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.routerListPolicies();
      const match = (list.policies || []).find(p => p.name === row.name);
      if (match) await client.routerRemovePolicy(match.id);
    } catch (err) {
      console.error(`[route-policies] agent delete failed (keeping DB change):`, err.message);
    }
    await pool.query('DELETE FROM route_policies WHERE id = $1 AND server_id = $2',
      [req.params.policyId, req.params.serverId]);
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
