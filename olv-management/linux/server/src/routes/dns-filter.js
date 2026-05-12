const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const enterpriseContext = require('../middleware/enterpriseContext');
const { isAdmin } = require('../constants/roles');
const { requireAdmin } = require('../middleware/serverAccess');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

async function getClient(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT id, access_mode FROM servers WHERE id = $1', [serverId])
    : await pool.query(
        `SELECT id, access_mode FROM servers WHERE id = $1 AND enterprise_id = $2`,
        [serverId, req.enterpriseId]
      );
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  if (rows[0].access_mode === 'public' && !isRoot) {
    throw Object.assign(new Error('Root access required for public server DNS filtering'), { status: 403 });
  }
  return new AgentClient(parseInt(serverId));
}

// POST /api/servers/:serverId/dns/:iface/enable
router.post('/:iface/enable', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsEnable(req.params.iface);
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/dns/:iface/disable
router.post('/:iface/disable', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsDisable(req.params.iface);
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/servers/:serverId/dns/:iface/blocked
router.get('/:iface/blocked', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsListBlocked(req.params.iface);
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/dns/:iface/block
router.post('/:iface/block', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsBlockDomain(req.params.iface, domain);
    res.status(201).json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/dns/:iface/unblock
router.post('/:iface/unblock', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'domain is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsUnblockDomain(req.params.iface, domain);
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/servers/:serverId/dns/categories
router.get('/categories', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsListCategories();
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/dns/:iface/category/enable
router.post('/:iface/category/enable', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { category } = req.body;
    if (!category) return res.status(400).json({ error: 'category is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsEnableCategory(req.params.iface, category);
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/dns/:iface/category/disable
router.post('/:iface/category/disable', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { category } = req.body;
    if (!category) return res.status(400).json({ error: 'category is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsDisableCategory(req.params.iface, category);
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/servers/:serverId/dns/stats
router.get('/stats', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.dnsGetStats();
    res.json(result);
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
