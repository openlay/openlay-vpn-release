const { Router } = require('express');
const { pool } = require('../db/pool');
const enterpriseContext = require('../middleware/enterpriseContext');
const { createSite, deleteSite } = require('../services/siteOrchestrator');

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
      'SELECT * FROM sites WHERE server_id = $1 ORDER BY name',
      [req.params.serverId]
    );
    res.json({ sites: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.get('/:siteId', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM sites WHERE id = $1 AND server_id = $2',
      [req.params.siteId, req.params.serverId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Site not found' });
    const artifacts = await pool.query(
      'SELECT * FROM site_artifacts WHERE site_id = $1 ORDER BY created_at',
      [req.params.siteId]
    );
    res.json({ ...rows[0], artifacts: artifacts.rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/sites — create a site. The orchestrator
// owns input validation after the bare minimum here, and any agent
// call failure rolls back atomically.
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const result = await createSite(parseInt(req.params.serverId), {
      name: req.body.name,
      description: req.body.description,
      localIface: req.body.localIface,
      localSubnet: req.body.localSubnet,
      remotePeerPubkey: req.body.remotePeerPubkey,
      remoteSubnet: req.body.remoteSubnet,
      remoteGateway: req.body.remoteGateway,
      enableNat: !!req.body.enableNat,
      policyFib: req.body.policyFib,
      enabled: req.body.enabled,
    });
    res.status(201).json(result);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Site name already exists on this server' });
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.delete('/:siteId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const result = await deleteSite(
      parseInt(req.params.serverId),
      parseInt(req.params.siteId)
    );
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PUT is intentionally minimal — only the "soft" fields that don't
// change artifact composition. Editing remote_subnet / local_iface
// would require tearing down + re-creating; force the admin to do
// that explicitly via DELETE + POST.
router.put('/:siteId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const set = [];
    const vals = [];
    let idx = 1;
    if (req.body.description !== undefined) { set.push(`description = $${idx++}`); vals.push(req.body.description); }
    if (req.body.enabled !== undefined)     { set.push(`enabled = $${idx++}`);     vals.push(!!req.body.enabled); }
    if (set.length === 0) {
      return res.status(400).json({ error: 'Only description/enabled are editable. DELETE + POST to change composition.' });
    }
    set.push('updated_at = NOW()');
    vals.push(req.params.siteId, req.params.serverId);
    const { rows } = await pool.query(
      `UPDATE sites SET ${set.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
      vals
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Site not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
