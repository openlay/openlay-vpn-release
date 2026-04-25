const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

// Helper to get agent client — verifies server access (enterprise or public)
async function getClient(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT url, api_token, access_mode, enterprise_id FROM servers WHERE id = $1', [serverId])
    : await pool.query(
        `SELECT url, api_token, access_mode, enterprise_id FROM servers
         WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
        [serverId, req.enterpriseId]
      );
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  return { client: new AgentClient(parseInt(serverId)), server: rows[0] };
}

// Only root can modify interfaces (create/delete/up/down/reload/save)
function requireRoot(req, res) {
  if (req.enterpriseRole !== 'root') {
    res.status(403).json({ error: 'Root access required for interface management' });
    return false;
  }
  return true;
}

// For public servers, non-root can only read (GET), not detail
function requireServerAccess(server, req, res) {
  if (server.access_mode === 'public' && req.enterpriseRole !== 'root') {
    res.status(403).json({ error: 'Public server: read-only access for non-root users' });
    return false;
  }
  return true;
}

// GET /api/servers/:serverId/interfaces
router.get('/', async (req, res) => {
  try {
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.listInterfaces();
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/interfaces/all
// Returns every system interface (physical + WireGuard) with an isWireGuard
// flag. Physical interfaces render as read-only on the client.
router.get('/all', async (req, res) => {
  try {
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.listAllInterfaces();
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/interfaces/:iface
router.get('/:iface', async (req, res) => {
  try {
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.getInterface(req.params.iface);

    // Override peer_count to match what the peers list endpoint shows.
    // The agent counts peers in its on-disk .conf only, but the peers list
    // also surfaces orphan peers_meta rows (peers tracked in DB but missing
    // from the agent — happens after agent reinstall/config wipe).
    // Without this override the Interfaces tab shows "0 peers" while
    // clicking through reveals many.
    const agentKeys = new Set(
      Array.isArray(data.peers)
        ? data.peers.map(p => p.public_key || p.publicKey).filter(Boolean)
        : []
    );
    const { rows: metaRows } = await pool.query(
      'SELECT public_key FROM peers_meta WHERE server_id = $1 AND interface_name = $2',
      [req.params.serverId, req.params.iface]
    );
    for (const row of metaRows) agentKeys.add(row.public_key);
    data.peer_count = agentKeys.size;
    delete data.peerCount;

    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces — root only
router.post('/', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;

    const { name, port, listenPort, address, addressV6, mtu, dns } = req.body;
    const actualPort = Number(listenPort || port);

    if (!name || typeof name !== 'string' || !/^[a-z0-9_-]+$/.test(name)) {
      return res.status(400).json({ error: 'name is required and must be lowercase alphanumeric (a-z, 0-9, _, -)' });
    }
    if (!address || typeof address !== 'string') {
      return res.status(400).json({ error: 'address (CIDR) is required' });
    }
    if (!Number.isInteger(actualPort) || actualPort < 51820 || actualPort > 51830) {
      return res.status(400).json({ error: 'port must be an integer between 51820 and 51830' });
    }
    if (mtu !== undefined && mtu !== null) {
      const mtuNum = Number(mtu);
      if (!Number.isInteger(mtuNum) || mtuNum < 576 || mtuNum > 65535) {
        return res.status(400).json({ error: 'mtu must be an integer between 576 and 65535' });
      }
    }

    const { client } = await getClient(req.params.serverId, req);
    const data = await client.createInterface({
      name, listenPort: actualPort, address, addressV6, mtu: mtu ? Number(mtu) : undefined, dns,
    });
    res.status(201).json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/interfaces/:iface — root only
router.delete('/:iface', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;

    // Block delete if any user is still assigned to this interface
    const { rows: assigned } = await pool.query(
      'SELECT COUNT(*)::int AS count FROM user_server_assignments WHERE server_id = $1 AND interface_name = $2',
      [req.params.serverId, req.params.iface]
    );
    if (assigned[0].count > 0) {
      return res.status(409).json({
        error: `Cannot delete interface: ${assigned[0].count} user(s) are still assigned to it. Please unassign them first.`,
      });
    }

    const { client } = await getClient(req.params.serverId, req);
    const data = await client.deleteInterface(req.params.iface);

    // Cascade-clean DB rows that referenced this iface by string name. Without
    // this, orphan rows linger and surface as: migrate empty-check failures,
    // ghost entries in the admin UI, and (worst) silent re-activation if a
    // future interface is created with the same name. All tables below hold
    // `iface`/`wan_iface` as VARCHAR with no FK, so cascade lives in code.
    const sid = req.params.serverId;
    const ifname = req.params.iface;
    const cascade = await pool.connect();
    try {
      await cascade.query('BEGIN');
      await cascade.query('DELETE FROM subnets              WHERE server_id = $1 AND interface_name = $2', [sid, ifname]);
      await cascade.query('DELETE FROM peers_meta           WHERE server_id = $1 AND interface_name = $2', [sid, ifname]);
      await cascade.query('DELETE FROM nat_rules            WHERE server_id = $1 AND wan_iface      = $2', [sid, ifname]);
      await cascade.query('DELETE FROM rdr_rules            WHERE server_id = $1 AND wan_iface      = $2', [sid, ifname]);
      await cascade.query('DELETE FROM routes               WHERE server_id = $1 AND iface          = $2', [sid, ifname]);
      await cascade.query('DELETE FROM route_policies       WHERE server_id = $1 AND (ingress_iface = $2 OR gateway_iface = $2)', [sid, ifname]);
      // firewall_zone_members: interface-type members holding this iface name
      await cascade.query(
        `DELETE FROM firewall_zone_members
          WHERE member_type = 'interface'
            AND member_value = $2
            AND zone_id IN (SELECT id FROM firewall_zones WHERE server_id = $1)`,
        [sid, ifname]
      );
      await cascade.query('COMMIT');
    } catch (cascadeErr) {
      await cascade.query('ROLLBACK');
      console.error('[interfaces] cascade cleanup failed:', cascadeErr.message);
      // Don't fail the whole request — the WG interface is already gone on
      // the agent. Surface a warning alongside the success payload.
      return res.json({ ...data, warning: `cascade cleanup failed: ${cascadeErr.message}` });
    } finally {
      cascade.release();
    }

    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/up — root only
router.post('/:iface/up', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.bringUp(req.params.iface);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/down — root only
router.post('/:iface/down', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.bringDown(req.params.iface);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/reload — root only
router.post('/:iface/reload', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.reloadInterface(req.params.iface);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/save — root only
router.post('/:iface/save', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.saveConfig(req.params.iface);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
