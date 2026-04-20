const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const { createLogicalRule, deleteLogicalRule, groupPhysicalRules, resyncRulesByUsers } = require('../services/ruleOrchestrator');
const enterpriseContext = require('../middleware/enterpriseContext');

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
  // Public servers: root only
  if (rows[0].access_mode === 'public' && !isRoot) {
    throw Object.assign(new Error('Root access required for public server firewall'), { status: 403 });
  }
  return new AgentClient(parseInt(serverId));
}

function requireAdmin(req, res) {
  if (!['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) {
    res.status(403).json({ error: 'Admin access required for firewall management' });
    return false;
  }
  return true;
}

// GET /api/servers/:serverId/firewall/policy
router.get('/policy', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallGetPolicy();
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PUT /api/servers/:serverId/firewall/policy
router.put('/policy', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallSetPolicy(req.body.defaultPolicy || req.body.default_policy);
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/firewall/all
router.get('/all', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallGetAllRules();
    // Group user rules by groupId so iOS sees 1 logical rule per "ACCEPT src=UserA" choice,
    // regardless of how many physical iptables entries it expanded to.
    const grouped = {};
    for (const [iface, rules] of Object.entries(result.interfaces || {})) {
      grouped[iface] = groupPhysicalRules(rules);
    }
    res.json({ ...result, interfaces: grouped });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/firewall/logs
router.get('/logs', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallGetLogs({
      ruleId: req.query.ruleId,
      ip: req.query.ip,
      iface: req.query.iface,
    });
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/firewall/:iface/rules
router.get('/:iface/rules', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallGetRules(req.params.iface);
    res.json({ ...result, user: groupPhysicalRules(result.user || []) });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/firewall/:iface/live
router.get('/:iface/live', async (req, res) => {
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallListLive(req.params.iface);
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/:iface/rules
router.post('/:iface/rules', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await getClient(req.params.serverId, req); // enforce access
    const logical = await createLogicalRule(parseInt(req.params.serverId), req.params.iface, req.body);
    res.status(201).json(logical);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/firewall/:iface/rules/:ruleId
// ruleId may be a logical groupId (delete all members) or a raw physical rule id.
router.delete('/:iface/rules/:ruleId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await getClient(req.params.serverId, req);
    const result = await deleteLogicalRule(parseInt(req.params.serverId), req.params.iface, req.params.ruleId);
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/resync-users
// Internal hook: re-expand rules that reference the given user IDs.
// Called by peer/device/static-IP mutation paths so iptables tracks the current IP set.
router.post('/resync-users', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await getClient(req.params.serverId, req);
    const userIds = Array.isArray(req.body?.userIds) ? req.body.userIds : [];
    await resyncRulesByUsers(parseInt(req.params.serverId), userIds);
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/firewall/:iface/flush
router.delete('/:iface/flush', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallFlushRules(req.params.iface);
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/:iface/block-ip
router.post('/:iface/block-ip', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { ip, direction } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallBlockIP(req.params.iface, ip, direction);
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/:iface/allow-ip
router.post('/:iface/allow-ip', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { ip, direction } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallAllowIP(req.params.iface, ip, direction);
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/:iface/block-port
router.post('/:iface/block-port', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { port, protocol } = req.body;
    if (!port) return res.status(400).json({ error: 'port is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallBlockPort(req.params.iface, port, protocol);
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/:iface/allow-port
router.post('/:iface/allow-port', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { port, protocol } = req.body;
    if (!port) return res.status(400).json({ error: 'port is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallAllowPort(req.params.iface, port, protocol);
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/:iface/block-peer
router.post('/:iface/block-peer', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { peerIP } = req.body;
    if (!peerIP) return res.status(400).json({ error: 'peerIP is required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallBlockPeer(req.params.iface, peerIP);
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/:iface/rate-limit
router.post('/:iface/rate-limit', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { peerIP, rateKbps } = req.body;
    if (!peerIP || !rateKbps) return res.status(400).json({ error: 'peerIP and rateKbps are required' });
    const client = await getClient(req.params.serverId, req);
    const result = await client.firewallRateLimitPeer(req.params.iface, peerIP, rateKbps);
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
