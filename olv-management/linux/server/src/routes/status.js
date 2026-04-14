const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

async function getClient(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT url, api_token FROM servers WHERE id = $1', [serverId])
    : await pool.query(
        `SELECT url, api_token FROM servers WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
        [serverId, req.enterpriseId]
      );
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  return new AgentClient(parseInt(serverId));
}

// GET /api/servers/:serverId/status/:iface
router.get('/:iface', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const data = await client.getStatus(req.params.iface);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/status/:iface/connected
router.get('/:iface/connected', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const activeWithin = req.query.activeWithinSeconds;
    const data = await client.getConnected(req.params.iface, activeWithin);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/status/:iface/transfer
router.get('/:iface/transfer', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const data = await client.getTransfer(req.params.iface);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/status/:iface/handshakes
router.get('/:iface/handshakes', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const data = await client.getHandshakes(req.params.iface);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/status/:iface/peers/:pubkey
router.get('/:iface/peers/:pubkey', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const data = await client.getPeerStatus(req.params.iface, decodeURIComponent(req.params.pubkey));
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/status/:iface/transfer/:pubkey
router.get('/:iface/transfer/:pubkey', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const data = await client.getPeerTransfer(req.params.iface, decodeURIComponent(req.params.pubkey));
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/audit-logs
router.get('/audit-logs', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const limit = parseInt(req.query.limit, 10) || 100;
    const offset = parseInt(req.query.offset, 10) || 0;
    const data = await client.getAuditLogs(limit, offset);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
