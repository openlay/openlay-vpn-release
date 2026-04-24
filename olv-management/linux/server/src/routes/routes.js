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

// GET /api/servers/:serverId/routes — all routes (optionally filter by iface).
router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { iface } = req.query;
    const params = [req.params.serverId];
    let sql = 'SELECT * FROM routes WHERE server_id = $1';
    if (iface) {
      sql += ' AND iface = $2';
      params.push(iface);
    }
    sql += ' ORDER BY iface, destination';
    const { rows } = await pool.query(sql, params);
    res.json({ routes: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/routes/live — raw netstat view from the agent.
router.get('/live', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const fib = req.query.fib ? parseInt(req.query.fib, 10) : 0;
    const client = new AgentClient(parseInt(req.params.serverId));
    const out = await client.routerListLive(fib);
    res.json(out);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/routes — create route on agent + DB.
// We write to the agent FIRST so a kernel failure (unreachable gateway)
// doesn't leave an orphan DB row. If the DB insert then fails (unique
// constraint), we roll the agent side back.
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { iface, destination, gateway, metric, fib, description, enabled } = req.body;
    if (!iface) return res.status(400).json({ error: 'iface is required' });
    if (!destination) return res.status(400).json({ error: 'destination is required' });

    const client = new AgentClient(parseInt(req.params.serverId));
    const agentRoute = await client.routerAddRoute(iface, {
      destination,
      gateway: gateway || undefined,
      metric: metric || 0,
      fib: fib || 0,
      description: description || '',
      enabled: enabled === undefined ? true : !!enabled,
    });

    try {
      const { rows } = await pool.query(
        `INSERT INTO routes (server_id, iface, destination, gateway, metric, fib, description, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [req.params.serverId, iface, destination, gateway || null, metric || 0, fib || 0, description || '', enabled === undefined ? true : !!enabled]
      );
      res.status(201).json({ ...rows[0], agentId: agentRoute.id });
    } catch (dbErr) {
      // Compensate — the agent now holds state the DB doesn't. Leaving
      // agent-only routes would confuse the next GET.
      try { await client.routerRemoveRoute(iface, agentRoute.id); } catch {}
      if (dbErr.code === '23505') return res.status(409).json({ error: 'Route already exists for this (iface, destination, fib)' });
      throw dbErr;
    }
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PUT /api/servers/:serverId/routes/:routeId — update fields.
// Gateway, metric, description, and enabled can change; destination and
// fib are immutable (would break the kernel key).
router.put('/:routeId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { gateway, metric, description, enabled } = req.body;

    const existing = await pool.query(
      'SELECT * FROM routes WHERE id = $1 AND server_id = $2',
      [req.params.routeId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Route not found' });
    const row = existing.rows[0];

    const fields = [];
    const values = [];
    let idx = 1;
    if (gateway !== undefined)     { fields.push(`gateway = $${idx++}`);     values.push(gateway || null); }
    if (metric !== undefined)      { fields.push(`metric = $${idx++}`);      values.push(metric); }
    if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }
    if (enabled !== undefined)     { fields.push(`enabled = $${idx++}`);     values.push(!!enabled); }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push('updated_at = NOW()');
    values.push(req.params.routeId, req.params.serverId);
    const { rows } = await pool.query(
      `UPDATE routes SET ${fields.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
      values
    );

    // Re-sync to agent. Kernel picture tracks the DB row state.
    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.routerListRoutes(row.iface);
      const match = (list.routes || []).find(r => r.destination === row.destination && (r.fib || 0) === row.fib);
      if (match) {
        const patch = {};
        if (gateway !== undefined) patch.gateway = gateway || '';
        if (metric !== undefined) patch.metric = metric;
        if (description !== undefined) patch.description = description;
        if (enabled !== undefined) patch.enabled = !!enabled;
        await client.routerUpdateRoute(row.iface, match.id, patch);
      }
    } catch (syncErr) {
      console.error(`[routes] agent sync failed:`, syncErr.message);
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/routes/:routeId
router.delete('/:routeId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const existing = await pool.query(
      'SELECT * FROM routes WHERE id = $1 AND server_id = $2',
      [req.params.routeId, req.params.serverId]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Route not found' });
    const row = existing.rows[0];

    const client = new AgentClient(parseInt(req.params.serverId));
    // Find agent-side ID by (destination, fib) match — DB doesn't store
    // the agent's opaque rt-<millis> ID.
    try {
      const list = await client.routerListRoutes(row.iface);
      const match = (list.routes || []).find(r => r.destination === row.destination && (r.fib || 0) === row.fib);
      if (match) await client.routerRemoveRoute(row.iface, match.id);
    } catch (agentErr) {
      // Agent offline — still delete the DB row so the next agent
      // reconnect + RestoreAll reconciles to an empty set.
      console.error(`[routes] agent delete failed (will still delete DB row):`, agentErr.message);
    }

    await pool.query('DELETE FROM routes WHERE id = $1 AND server_id = $2',
      [req.params.routeId, req.params.serverId]);
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/routes/flush?iface=wg0 — wipe all routes on iface.
router.post('/flush', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { iface } = req.body || {};
    if (!iface) return res.status(400).json({ error: 'iface is required' });
    const client = new AgentClient(parseInt(req.params.serverId));
    try { await client.routerFlushRoutes(iface); } catch (err) {
      console.error(`[routes] agent flush failed:`, err.message);
    }
    const { rowCount } = await pool.query(
      'DELETE FROM routes WHERE server_id = $1 AND iface = $2',
      [req.params.serverId, iface]
    );
    res.json({ deleted: rowCount });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
